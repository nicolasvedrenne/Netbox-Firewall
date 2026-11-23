import os


def pytest_ignore_collect(collection_path):
    if "integration" in collection_path.parts and not os.environ.get("DJANGO_SETTINGS_MODULE"):
        return True
    return None
