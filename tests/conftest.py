import pytest


@pytest.fixture(autouse=True)
def _isolate_user_config(tmp_path, monkeypatch):
    """Never let a developer's real ~/.awr_analyzer/config.json affect tests."""
    monkeypatch.setenv("AWR_ANALYZER_CONFIG", str(tmp_path / "no-such-config.json"))
