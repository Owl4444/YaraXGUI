"""Compatibility launcher; the application lives in yaraxgui.app."""

if __name__ == "__main__":
    # Frozen analysis workers must dispatch before importing Qt or the GUI.
    from multiprocessing import freeze_support

    freeze_support()

from yaraxgui.app import MainWindow, main

if __name__ == "__main__":
    raise SystemExit(main())
