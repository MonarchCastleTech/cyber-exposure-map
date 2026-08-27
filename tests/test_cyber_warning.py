import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline"))

import cyber_warning_model as model


NOW = datetime(2026, 8, 27, tzinfo=timezone.utc)


def _catalog(current=3, baseline=1):
    rows = []
    for index in range(current):
        rows.append({
            "cveID": f"CVE-2026-{9000 + index}",
            "dateAdded": (NOW.date() - timedelta(days=index)).isoformat(),
            "dueDate": (NOW.date() + timedelta(days=3)).isoformat(),
            "knownRansomwareCampaignUse": "Unknown",
        })
    for week in range(1, 27):
        for index in range(baseline):
            rows.append({
                "cveID": f"CVE-2025-{week:02d}{index:02d}",
                "dateAdded": (NOW.date() - timedelta(days=week * 7 + 1)).isoformat(),
                "knownRansomwareCampaignUse": "Unknown",
            })
    return {"catalog_version": "test", "vulnerabilities": rows}


def _frontier(accelerated=2):
    rows = []
    for index in range(5):
        current = 0.80 - index * 0.05
        previous = current - 0.10 if index < accelerated else current
        rows.append({
            "cve": f"CVE-2026-{8000 + index}",
            "epss": str(current),
            "percentile": "0.99",
            "date": NOW.date().isoformat(),
            "time_series": [{
                "epss": str(previous),
                "percentile": "0.98",
                "date": (NOW.date() - timedelta(days=8)).isoformat(),
            }],
        })
    return {"threshold": 0.1, "total_above_threshold": 5000, "rows": rows}


def _event(title, domain):
    return {
        "title": title,
        "domain": domain,
        "url": f"https://{domain}/story",
        "seendate": NOW.strftime("%Y%m%dT%H%M%SZ"),
    }


def test_warning_contract_is_explainable_and_not_breach_probability():
    events = [
        _event("Proof of concept released for CVE-2026-7000", "one.example"),
        _event("CVE-2026-7000 weaponized in mass scanning", "two.example"),
    ]
    warning = model.build_cyber_warning(_catalog(), _frontier(), events, now=NOW)

    assert warning["classification"] == "global-exploitation-pressure-not-organisation-breach-probability"
    assert warning["horizon"] == "next 30 days"
    assert warning["method"]["weights"] == model.WEIGHTS
    assert {row["id"] for row in warning["components"]} == set(model.WEIGHTS)
    assert warning["concurrence"]["active"] is True
    assert warning["concurrence"]["score_bonus"] == 5.0


def test_kev_burst_uses_prior_non_overlapping_weeks():
    component = model._kev_component(_catalog(current=5, baseline=1), NOW)
    assert component["recent_7d_count"] == 5
    assert component["prior_7d_count"] == 1
    assert component["baseline_weeks"] == 26
    assert component["score"] >= 35


def test_epss_component_detects_seven_day_acceleration():
    component = model._epss_component(_frontier(accelerated=3), NOW)
    assert component["accelerated_7d_count"] == 3
    assert component["maximum_7d_delta"] == 0.1
    assert component["score"] >= 35


def test_missing_components_are_availability_renormalized():
    warning = model.build_cyber_warning({}, {}, [_event("Routine cyber news", "one.example")], now=NOW)
    narrative = next(row for row in warning["components"] if row["id"] == "exploit_narrative_pressure")
    assert warning["score"] == narrative["score"]
    assert warning["data_health"]["available_components"] == 1


def test_history_is_bounded_to_180_snapshots():
    previous = {"history": [{"timestamp": str(i), "score": i} for i in range(250)]}
    warning = model.build_cyber_warning(_catalog(), _frontier(), [], previous=previous, now=NOW)
    assert len(warning["history"]) == 180


def test_rerun_within_one_hour_replaces_last_history_point():
    previous = {"history": [{"timestamp": (NOW - timedelta(minutes=20)).isoformat(), "score": 99}]}
    warning = model.build_cyber_warning(_catalog(), _frontier(), [], previous=previous, now=NOW)
    assert len(warning["history"]) == 1
    assert warning["history"][0]["score"] != 99
