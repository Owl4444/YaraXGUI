"""Retain legacy analysis threads until Qt reports actual thread completion."""
import atexit
from PySide6.QtCore import QObject, Slot


class _Keeper(QObject):
    def __init__(self):
        super().__init__()
        self.threads = set()

    @Slot()
    def done(self):
        thread = self.sender()
        self.threads.discard(thread)
        thread.deleteLater()


_keeper = None


def retain_thread(thread):
    global _keeper
    if _keeper is None:
        _keeper = _Keeper()
    if thread not in _keeper.threads:
        _keeper.threads.add(thread)
        thread.finished.connect(_keeper.done)


def stop_thread(thread):
    if thread is not None:
        thread.requestInterruption()
        if hasattr(thread, 'cancel'):
            thread.cancel()


def _shutdown():
    if _keeper is not None:
        for thread in list(_keeper.threads):
            stop_thread(thread)
        for thread in list(_keeper.threads):
            thread.wait()


atexit.register(_shutdown)
