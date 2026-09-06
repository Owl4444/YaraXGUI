"""Bounded formatting for interactive adapters; no queued or orphaned workers."""
import multiprocessing
import threading
import time

from .compiler import Compiler, CompileOptions
from .formatter import FormatError, FormatOptions, format_source

MAX_INTERACTIVE_BYTES = 256 * 1024
MAX_AUTOMATIC_BYTES = 64 * 1024


class FormatBusy(FormatError):
    pass


class FormatTimeout(FormatError):
    pass


class SourceTooLarge(FormatError):
    pass


def check_source_size(text, limit=MAX_INTERACTIVE_BYTES):
    # Avoid allocating an encoded copy of an already oversized document.
    if len(text) > limit or len(text.encode("utf-8")) > limit:
        raise SourceTooLarge(f"Source exceeds the {limit // 1024} KiB interactive limit; original source retained")


def _format_worker(connection, text, compile_options, format_options):
    try:
        result = format_source(text, compiler=Compiler(compile_options), options=format_options)
        check_source_size(result, 2 * 1024 * 1024)
        connection.send((result, None, ()))
    except FormatError as exc:
        connection.send((None, str(exc), exc.diagnostics))
    except Exception:
        connection.send((None, "Formatting worker failed; original source retained", ()))
    finally:
        connection.close()


class FormatRunner:
    """One active process per runner, with a minimum interval between starts.

    Share a runner across requests. Call from an adapter's background thread:
    this method blocks its caller, while work runs in a disposable process.
    The synchronous ``format_source`` API remains available for batch tools.
    """

    def __init__(self, *, timeout=5.0, interval=1.0, max_bytes=MAX_INTERACTIVE_BYTES):
        if timeout <= 0 or interval < 0 or max_bytes <= 0:
            raise ValueError("Invalid formatting limits")
        self.timeout = timeout
        self.interval = interval
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._next_start = 0.0
        self._context = multiprocessing.get_context("spawn")

    def format(self, text, *, compile_options=CompileOptions(), options=FormatOptions()):
        check_source_size(text, self.max_bytes)
        if not self._lock.acquire(blocking=False):
            raise FormatBusy("Formatting is already running; try again when it finishes")
        receiver = sender = process = None
        started = False
        try:
            now = time.monotonic()
            if now < self._next_start:
                raise FormatBusy("Please wait a moment before formatting again")
            self._next_start = now + self.interval
            receiver, sender = self._context.Pipe(duplex=False)
            process = self._context.Process(target=_format_worker,
                args=(sender, text, compile_options, options), daemon=True)
            process.start()
            started = True
            sender.close()
            if not receiver.poll(self.timeout):
                raise FormatTimeout(f"Formatting exceeded {self.timeout:g} seconds; original source retained")
            try:
                result, error, diagnostics = receiver.recv()
            except EOFError:
                raise FormatError("Formatting worker stopped; original source retained") from None
            if error:
                raise FormatError(error, diagnostics)
            return result
        finally:
            if started:
                # Also clean up if the caller fails while receiving a result.
                process.join(timeout=0.1)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=1)
                if process.is_alive():
                    process.kill()
                    process.join()
                process.close()
            if receiver is not None:
                receiver.close()
            if sender is not None:
                sender.close()
            self._lock.release()
