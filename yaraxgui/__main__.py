"""Launch the desktop application with python -m yaraxgui."""

if __name__ == "__main__":
    from multiprocessing import freeze_support

    freeze_support()

    from yaraxgui.app import main

    raise SystemExit(main())
