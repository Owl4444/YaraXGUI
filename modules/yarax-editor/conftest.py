"""Keep this independent project's suites out of the host application's run."""
from pathlib import Path


def pytest_ignore_collect(collection_path, config):
    return (config.rootpath != Path(__file__).parent
            and collection_path.name in {"tests", "browser_tests"})
