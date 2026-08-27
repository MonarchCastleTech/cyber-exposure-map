"""Explainable global cyber-exploitation pressure model.

The index is an analyst-triage signal. It is not an organisation-specific
breach probability and it does not infer whether any product is deployed.
"""

from __future__ import annotations

import math
import re
import statistics
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlparse


WEIGHTS = {
    "kev_addition_pressure": 0.40,
    "epss_frontier_momentum": 0.35,
    "exploit_narrative_pressure": 0.25,
}

NARRATIVE_BASKETS = {
    "weaponization": (
        "proof of concept", "proof-of-concept", "poc released", "exploit code",
        "weaponized", "weaponised", "metasploit",
    ),
    "mass_scanning": (
        "mass scanning", "mass exploitation", "internet-wide scanning",
        "scanning activity", "honeypot", "botnet",
    ),
    "perimeter_access": (
        "pre-auth", "preauth", "authentication bypass", "remote code execution",
        "zero-day", "zero day", "0-day", "initial access",
    ),
    "campaign_shift": (
        "active exploitation", "exploit chain", "ransomware", "supply chain",
        "emergency patch", "out-of-band patch", "patch bypass",
    ),
}

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, float(value)))


def _parse_date(value) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def _parse_datetime(value) -> datetime | None:
    text = str(value or "")
    for fmt in ("%Y%m%dT%H%M%SZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _robust_z(current: float, baseline: list[float]) -> float:
    clean = [float(value) for value in baseline if math.isfinite(float(value))]
    if len(clean) < 4:
        return 0.0
    median = statistics.median(clean)
    mad = statistics.median(abs(value - median) for value in clean)
    if mad > 1e-9:
        return (current - median) / (1.4826 * mad)
    spread = statistics.pstdev(clean)
    return (current - median) / spread if spread > 1e-9 else 0.0


def _domain(event: dict) -> str:
    value = str(event.get("domain") or "").strip().lower()
    if value and value != "news.google.com":
        return value
    host = urlparse(str(event.get("url") or "")).hostname or ""
    return host.lower().removeprefix("www.") or value or "unknown"


def _event_text(event: dict) -> str:
    return " ".join(str(event.get(key) or "") for key in ("title", "description", "summary")).lower()


def _kev_component(catalog: dict, now: datetime) -> dict:
    vulnerabilities = list(catalog.get("vulnerabilities") or [])
    weekly = [0 for _ in range(27)]
    recent = []
    for item in vulnerabilities:
        added = _parse_date(item.get("dateAdded"))
        if not added:
            continue
        age = (now.date() - added).days
        if 0 <= age < 7:
            recent.append(item)
        if 0 <= age < 27 * 7:
            weekly[age // 7] += 1

    baseline = [float(value) for value in weekly[1:] if value >= 0]
    anomaly_z = _robust_z(float(weekly[0]), baseline)
    ransomware = sum(
        1 for item in recent
        if str(item.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
    )
    due_soon = sum(
        1 for item in recent
        if (due := _parse_date(item.get("dueDate"))) and 0 <= (due - now.date()).days <= 7
    )
    density_score = _clamp(len(recent) * 7.5, high=50)
    anomaly_score = _clamp(max(0.0, anomaly_z) * 12.5, high=40)
    urgency_score = _clamp(ransomware * 4 + due_soon, high=10)
    evidence = sorted(recent, key=lambda row: str(row.get("dateAdded") or ""), reverse=True)[:12]
    return {
        "id": "kev_addition_pressure",
        "label": "CISA exploited-vulnerability burst",
        "available": bool(vulnerabilities),
        "score": round(_clamp(density_score + anomaly_score + urgency_score), 1),
        "catalog_count": len(vulnerabilities),
        "recent_7d_count": len(recent),
        "prior_7d_count": weekly[1],
        "baseline_weeks": len(baseline),
        "baseline_weekly_median": round(statistics.median(baseline), 2) if baseline else 0.0,
        "anomaly_z": round(anomaly_z, 2),
        "ransomware_known_7d": ransomware,
        "due_within_7d": due_soon,
        "catalog_version": catalog.get("catalog_version") or catalog.get("catalogVersion"),
        "released_at": catalog.get("date_released") or catalog.get("dateReleased"),
        "evidence": evidence,
        "retained": bool(catalog.get("retained") or catalog.get("cached")),
    }


def _score_seven_days_ago(row: dict, now: datetime) -> float:
    target = now.date() - timedelta(days=7)
    candidates = []
    for point in row.get("time_series") or row.get("time-series") or []:
        observed = _parse_date(point.get("date"))
        if observed and observed <= target:
            candidates.append((observed, float(point.get("epss") or 0)))
    if not candidates:
        return float(row.get("epss") or 0)
    return max(candidates, key=lambda item: item[0])[1]


def _epss_component(frontier: dict, now: datetime) -> dict:
    rows = list(frontier.get("rows") or [])
    evaluated = []
    for row in rows:
        current = float(row.get("epss") or 0)
        previous = _score_seven_days_ago(row, now)
        delta = current - previous
        relative = delta / previous if previous > 0 else (1.0 if delta > 0 else 0.0)
        evaluated.append({
            "cve": row.get("cve"),
            "epss": round(current, 5),
            "percentile": round(float(row.get("percentile") or 0), 5),
            "delta_7d": round(delta, 5),
            "relative_delta_7d": round(relative, 3),
            "date": row.get("date"),
            "url": f"https://api.first.org/data/v1/epss?cve={row.get('cve')}",
        })
    accelerated = [row for row in evaluated if row["delta_7d"] >= 0.05 or (row["delta_7d"] >= 0.01 and row["relative_delta_7d"] >= 0.5)]
    top_current = sorted((row["epss"] for row in evaluated), reverse=True)[:10]
    positive_deltas = sorted((max(0.0, row["delta_7d"]) for row in evaluated), reverse=True)
    base_score = (statistics.mean(top_current) * 25) if top_current else 0.0
    breadth_score = _clamp(len(accelerated) * 8, high=50)
    velocity_score = _clamp((positive_deltas[0] if positive_deltas else 0.0) * 100, high=25)
    evidence = sorted(evaluated, key=lambda row: (row["delta_7d"], row["epss"]), reverse=True)[:12]
    return {
        "id": "epss_frontier_momentum",
        "label": "EPSS pre-KEV exploitation frontier",
        "available": bool(rows),
        "score": round(_clamp(base_score + breadth_score + velocity_score), 1),
        "frontier_count": len(rows),
        "global_above_threshold": int(frontier.get("total_above_threshold") or 0),
        "threshold": float(frontier.get("threshold") or 0.1),
        "accelerated_7d_count": len(accelerated),
        "maximum_7d_delta": round(positive_deltas[0] if positive_deltas else 0.0, 5),
        "mean_top10_probability": round(statistics.mean(top_current), 5) if top_current else 0.0,
        "timeseries_available": sum(bool(row.get("time_series") or row.get("time-series")) for row in rows),
        "evidence": evidence,
        "retained": bool(frontier.get("retained") or frontier.get("cached")),
    }


def _narrative_component(events: list[dict]) -> dict:
    evidence = []
    basket_sources = {key: set() for key in NARRATIVE_BASKETS}
    all_domains = {_domain(event) for event in events if _domain(event) != "unknown"}
    cves = set()
    for event in events:
        text = _event_text(event)
        matches = {
            basket: sorted({term for term in terms if term in text})
            for basket, terms in NARRATIVE_BASKETS.items()
        }
        matches = {basket: terms for basket, terms in matches.items() if terms}
        event_cves = sorted({match.upper() for match in CVE_PATTERN.findall(text)})
        cves.update(event_cves)
        if not matches:
            continue
        source = _domain(event)
        for basket in matches:
            if source != "unknown":
                basket_sources[basket].add(source)
        evidence.append({
            "title": event.get("title") or "Untitled signal",
            "url": event.get("url"),
            "source": source,
            "observed_at": event.get("seendate") or event.get("date"),
            "baskets": sorted(matches),
            "terms": sorted({term for terms in matches.values() for term in terms}),
            "cves": event_cves,
        })
    confirmed = sum(1 for sources in basket_sources.values() if len(sources) >= 2)
    share = len(evidence) / max(len(events), 1)
    score = _clamp(share * 150 + confirmed * 10 + min(len(cves), 10) * 2)
    return {
        "id": "exploit_narrative_pressure",
        "label": "Cross-source exploit precursor language",
        "available": bool(events),
        "score": round(score, 1),
        "events_considered": len(events),
        "matched_event_count": len(evidence),
        "matched_share": round(share, 4),
        "independent_sources": len(all_domains),
        "unique_cves": len(cves),
        "cross_source_baskets": confirmed,
        "baskets": [
            {"id": basket, "independent_sources": len(sources), "cross_source_confirmed": len(sources) >= 2}
            for basket, sources in basket_sources.items()
        ],
        "evidence": evidence[:12],
    }


def _level(score: float) -> str:
    if score >= 75:
        return "SEVERE"
    if score >= 55:
        return "ELEVATED"
    if score >= 35:
        return "WATCH"
    return "BASELINE"


def build_cyber_warning(catalog: dict, frontier: dict, events: list[dict], previous: dict | None = None, now: datetime | None = None) -> dict:
    """Create one reproducible, availability-aware warning snapshot."""

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    components = [
        _kev_component(catalog, now),
        _epss_component(frontier, now),
        _narrative_component(events),
    ]
    available = [component for component in components if component["available"]]
    denominator = sum(WEIGHTS[component["id"]] for component in available)
    base_score = (
        sum(component["score"] * WEIGHTS[component["id"]] for component in available) / denominator
        if denominator else 0.0
    )
    elevated = [component["id"] for component in available if component["score"] >= 35]
    concurrence_bonus = 5.0 if len(elevated) >= 2 else 0.0
    score = _clamp(base_score + concurrence_bonus)

    kev, epss, narrative = components
    cisa_quality = 0.85 if kev.get("retained") else 1.0
    epss_quality = 0.85 if epss.get("retained") else 1.0
    confidence_score = 100 * (
        0.45 * min(1.0, kev["catalog_count"] / 1000) * cisa_quality
        + 0.35 * min(1.0, epss["frontier_count"] / 30) * epss_quality
        + 0.10 * min(1.0, narrative["events_considered"] / 30)
        + 0.10 * min(1.0, narrative["independent_sources"] / 10)
    )
    confidence = "HIGH" if confidence_score >= 75 else "MEDIUM" if confidence_score >= 45 else "LOW"
    reasons = {
        "kev_addition_pressure": "CISA additions are elevated against the previous 26 weekly windows.",
        "epss_frontier_momentum": "High-EPSS vulnerabilities outside KEV are accelerating over seven days.",
        "exploit_narrative_pressure": "Weaponization or exploitation language is confirmed across distinct named sources.",
    }
    alerts = [
        {
            "id": component["id"],
            "title": component["label"],
            "score": component["score"],
            "level": _level(component["score"]),
            "why": reasons[component["id"]],
        }
        for component in available if component["score"] >= 35
    ]
    alerts.sort(key=lambda row: row["score"], reverse=True)

    history = list((previous or {}).get("history") or [])[-179:]
    if history:
        last_issued = _parse_datetime(history[-1].get("timestamp"))
        if last_issued and timedelta(0) <= now - last_issued < timedelta(hours=1):
            history.pop()
    history.append({
        "timestamp": now.isoformat(),
        "score": round(score, 1),
        "level": _level(score),
        "components": {component["id"]: component["score"] for component in components},
    })
    return {
        "issued_at": now.isoformat(),
        "horizon": "next 30 days",
        "classification": "global-exploitation-pressure-not-organisation-breach-probability",
        "score": round(score, 1),
        "level": _level(score),
        "confidence": confidence,
        "confidence_score": round(confidence_score, 1),
        "components": components,
        "concurrence": {
            "active": len(elevated) >= 2,
            "elevated_components": elevated,
            "score_bonus": concurrence_bonus,
        },
        "alerts": alerts,
        "history": history,
        "data_health": {
            "cisa_catalog_count": kev["catalog_count"],
            "epss_frontier_count": epss["frontier_count"],
            "epss_timeseries_count": epss["timeseries_available"],
            "news_events_considered": narrative["events_considered"],
            "independent_news_sources": narrative["independent_sources"],
            "available_components": len(available),
            "retained_components": [component["id"] for component in components if component.get("retained")],
        },
        "method": {
            "name": "Cyber exploitation precursor concurrence model v1",
            "aggregation": "availability-renormalized weighted mean plus disclosed 5-point concurrence bonus",
            "weights": WEIGHTS,
            "kev_window": "current seven-day additions versus 26 prior non-overlapping weekly counts using median/MAD robust z-score",
            "epss_window": "top non-KEV CVEs above 0.10 EPSS; current level and seven-day probability acceleration",
            "narrative_taxonomy": NARRATIVE_BASKETS,
            "warning": "This is global triage pressure, not proof of compromise or an organisation-specific risk score.",
        },
        "sources": [
            {"name": "CISA Known Exploited Vulnerabilities", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
            {"name": "CISA KEV JSON", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
            {"name": "FIRST EPSS API", "url": "https://api.first.org/epss/"},
            {"name": "FIRST EPSS methodology and research", "url": "https://www.first.org/epss/research.html"},
        ],
    }
