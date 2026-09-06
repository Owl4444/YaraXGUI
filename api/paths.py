"""Filesystem access policy for API requests and disposable scan workers."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import tempfile


class FilePolicy:
    def __init__(self, roots, upload_dir, protected=()):
        self.roots = tuple(Path(root).resolve() for root in (*roots, upload_dir))
        self.protected = tuple(Path(path).resolve() for path in protected if path)

    def validate(self, path):
        candidate = Path(path).resolve()
        if not any(candidate.is_relative_to(root) for root in self.roots):
            raise PermissionError('Path is outside the configured sample roots')
        for protected in self.protected:
            if candidate == protected or (candidate.parent == protected.parent
                    and candidate.name in {protected.name + suffix for suffix in ('-wal', '-shm', '-journal')}):
                raise PermissionError('Server configuration and database files are not sample files')
        return candidate

    @contextmanager
    def open(self, path):
        candidate = self.validate(path)
        root = next(root for root in self.roots if candidate.is_relative_to(root))
        # On POSIX, anchor traversal to directory descriptors. Reject symlink
        # swaps of any component, not just the final file, after validation.
        if os.name == 'posix' and os.open in os.supports_dir_fd:
            fds = []
            try:
                directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                fds.append(directory)
                parts = candidate.relative_to(root).parts
                if not parts:
                    raise ValueError('Path is not a file')
                for part in parts[:-1]:
                    directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    fds.append(directory)
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                with os.fdopen(fd, 'rb') as stream:
                    opened = os.fstat(stream.fileno())
                    self._check_inode(opened)
                    if not stat.S_ISREG(opened.st_mode):
                        raise ValueError('Path is not a regular file')
                    yield stream
            finally:
                for fd in reversed(fds):
                    os.close(fd)
        else:
            # Windows deployments additionally require ACL-isolated sample
            # directories: Python has no portable openat/no-reparse equivalent.
            if candidate.is_symlink() or not candidate.is_file():
                raise ValueError('Path is not a regular file')
            with candidate.open('rb') as stream:
                self.validate(candidate)
                self._check_inode(os.fstat(stream.fileno()))
                yield stream

    def _check_inode(self, opened):
        for protected in self.protected:
            for path in (protected, *(protected.with_name(protected.name + suffix)
                                      for suffix in ('-wal', '-shm', '-journal'))):
                try:
                    info = path.stat()
                except FileNotFoundError:
                    continue
                if (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino):
                    raise PermissionError('Server files cannot be accessed through hard links')


def configured_file_policy():
    return FilePolicy(
        [p.strip() for p in os.environ.get('YARAXGUI_ALLOWED_ROOTS', '').split(',') if p.strip()],
        os.environ.get('YARAXGUI_UPLOAD_DIR', str(Path(tempfile.gettempdir()) / 'yaraxgui_uploads')),
        protected=[os.environ.get('YARAXGUI_REPO_DB', str(Path(__file__).parent / 'rules.db')),
                   os.environ.get('YARAXGUI_SSL_KEYFILE'), os.environ.get('YARAXGUI_SSL_CERTFILE'),
                   str(Path(__file__).resolve().parents[1] / '.env'),
                   str(Path(__file__).resolve().parents[1] / 'config/settings.json')])
