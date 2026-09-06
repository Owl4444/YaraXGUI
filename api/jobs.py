"""Bounded server jobs. CPU work stays out of the ASGI process."""
import asyncio
from datetime import datetime, timezone
import os

from .scan_manager import ScanJob
from .workers import ProcessRunner, WorkerBusy
from yaraxgui.scanning.scanner import YaraScanner


class SecureScanManager:
    def __init__(self, policy=None, runner=None):
        from .security import SecurityPolicy
        self.policy = policy or SecurityPolicy.from_env()
        self.runner = runner or ProcessRunner()
        self.scanner = YaraScanner()
        self._jobs = {}
        self._max_jobs = 16
        self._max_active = 2
        self._tasks = set()

    def _admit(self):
        if sum(job.status in ('queued', 'running') for job in self._jobs.values()) >= self._max_active:
            raise WorkerBusy('At most two scans can be active; cancel or wait for one to finish')
        for key, job in list(self._jobs.items()):
            if len(self._jobs) < self._max_jobs:
                break
            if job.status not in ('queued', 'running'):
                del self._jobs[key]

    def create_job(self, rule_text, paths, recursive=True, exclusions=None):
        self._admit()
        job = ScanJob(rule_text, paths, recursive, exclusions)
        self._jobs[job.job_id] = job
        return job

    def create_mwdb_job(self, rule_text, mwdb_url, mwdb_token, query=None,
                        file_hash=None, limit=100, batch_size=50,
                        include_misses=False, parallel_downloads=4):
        if not self.policy.mwdb_url or mwdb_url.rstrip('/') != self.policy.mwdb_url:
            raise PermissionError('MWDB scans require the server-configured YARAXGUI_MWDB_URL')
        self._admit()
        job = ScanJob(rule_text, [], source='mwdb')
        job.mwdb_url, job.mwdb_token = self.policy.mwdb_url, mwdb_token
        job.mwdb_query, job.mwdb_file_hash = query, file_hash
        job.mwdb_limit = min(limit, 1000)
        job.mwdb_batch_size = min(batch_size, 100)
        job.include_misses = include_misses
        self._jobs[job.job_id] = job
        return job

    def submit(self, job):
        task = asyncio.create_task(self.run_job(job))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def shutdown(self):
        for job in self._jobs.values():
            job.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    async def run_job(self, job):
        if job.cancelled:
            job.status = 'cancelled'
            job.mwdb_token = ''
            job.completed_at = datetime.now(timezone.utc).isoformat()
            return
        job.status = 'running'
        payload = {'text': job.rule_text, 'paths': job.paths, 'recursive': job.recursive,
                   'exclusions': job.exclusions, 'allow_includes': False}
        if job.source == 'mwdb':
            payload.update(url=job.mwdb_url, token=job.mwdb_token, query=job.mwdb_query,
                           file_hash=job.mwdb_file_hash, limit=job.mwdb_limit,
                           batch_size=job.mwdb_batch_size, include_misses=job.include_misses)
        loop = asyncio.get_running_loop()
        def progress(info):
            loop.call_soon_threadsafe(job.progress.update, info)
        try:
            job.results = await asyncio.to_thread(self.runner.run,
                'mwdb' if job.source == 'mwdb' else 'scan', payload,
                cancelled=lambda: job.cancelled, progress=progress,
                timeout=int(os.environ.get('YARAXGUI_SCAN_TIMEOUT', '60')))
            job.status = 'cancelled' if job.cancelled else 'completed'
            job.progress.update(scanned=job.results.get('stats', {}).get('scanned', 0), current_file='')
            job.progress['total'] = job.progress['scanned']
        except InterruptedError:
            job.status = 'cancelled'
        except Exception as exc:
            job.status = 'failed'
            job.error = str(exc)
            job.results = {'hits': [], 'misses': [], 'stats': {}, 'error_messages': [str(exc)]}
        finally:
            job.mwdb_token = ''
            job.completed_at = datetime.now(timezone.utc).isoformat()

    def get_job(self, job_id):
        return self._jobs.get(job_id)

    def list_jobs(self):
        return [job.to_status_dict() for job in self._jobs.values()]
