import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline"))

import cyber_exposure_map_pipeline as pipeline
import data_fetcher


def test_recent_cache_is_accepted_and_expired_cache_is_rejected(tmp_path, monkeypatch):
    cache = tmp_path / "feed.json"
    monkeypatch.setattr(data_fetcher, "_cache_path", lambda name: cache)
    cache.write_text(json.dumps({
        "fetched_at": (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),
        "data": {"rows": [1]},
    }), encoding="utf-8")
    assert data_fetcher._read_recent_cache("feed") == {"rows": [1]}

    cache.write_text(json.dumps({
        "fetched_at": (datetime.now(timezone.utc) - timedelta(hours=73)).isoformat(),
        "data": {"rows": [1]},
    }), encoding="utf-8")
    assert data_fetcher._read_recent_cache("feed") is None


def test_previous_sources_are_retained_only_for_72_hours():
    fresh_previous = {
        "meta": {"generated": (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()},
        "live_data": {"cisa_catalog": {"vulnerabilities": [{"cveID": "CVE-1"}]}},
    }
    live = {}
    notes = pipeline.retain_previous(live, fresh_previous)
    assert live["cisa_catalog"]["retained"] is True
    assert notes

    expired_previous = {
        "meta": {"generated": (datetime.now(timezone.utc) - timedelta(hours=73)).isoformat()},
        "live_data": fresh_previous["live_data"],
    }
    expired_live = {}
    assert pipeline.retain_previous(expired_live, expired_previous) == []
    assert expired_live == {}


def test_pipeline_preserves_last_good_when_official_sources_are_absent(monkeypatch):
    monkeypatch.setattr(pipeline, "load_config", lambda: {"project": {"id": "cyber-exposure-map", "name": "CEM"}})
    monkeypatch.setattr(pipeline, "load_previous", lambda: {})
    monkeypatch.setattr(pipeline, "extract_live_data", lambda config: {})
    assert pipeline.main() is False


def test_keyless_pipeline_writes_deterministic_snapshot(tmp_path, monkeypatch):
    article = {"title": "Public signal", "url": "https://example.org/signal", "domain": "example.org", "tone": 0, "seendate": "20260830T120000Z"}
    live = {
        "news_articles": [article],
        "cisa_catalog": {"vulnerabilities": [{"cveID": "CVE-1"}]},
        "epss_frontier": {"rows": [{"cve": "CVE-2", "epss": .8}]},
    }
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(pipeline, "load_config", lambda: {"project": {"id": "cyber-exposure-map", "name": "CEM"}})
    monkeypatch.setattr(pipeline, "load_previous", lambda: {})
    monkeypatch.setattr(pipeline, "extract_live_data", lambda config: live)
    monkeypatch.setattr(pipeline, "build_cyber_warning", lambda *args, **kwargs: {"score": 0})
    monkeypatch.setattr(pipeline, "analyze_with_llm", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("LLM must stay optional")))
    assert pipeline.main() is True
    payload = json.loads((tmp_path / "data" / "output.json").read_text(encoding="utf-8"))
    assert payload["llm_summary"] == ""
    assert payload["events"] == [article]
