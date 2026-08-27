# -*- coding: utf-8 -*-
"""Canonical project data pipeline. Identity and sources come from config.yaml."""
import json
import os
import sys
from datetime import datetime, timezone

import yaml

sys.path.insert(0, os.path.dirname(__file__))
from cyber_warning_model import build_cyber_warning
from data_fetcher import fetch_cisa_kev, fetch_epss_frontier, fetch_google_news_rss, safe_fetch
from openrouter_llm import analyze_with_llm

SNAPSHOT_SIZE = 50
EVENT_LIMIT = 15


def load_config():
    path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def load_previous():
    try:
        with open("data/output.json", "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}


def extract_live_data(config):
    live = {}
    query = config.get("news_query") or "geopolitical risk"
    print(f"[LIVE] News query: {query}")

    catalog = safe_fetch(fetch_cisa_kev) or {}
    if catalog.get("vulnerabilities"):
        live["cisa_catalog"] = catalog
        print(f"  CISA KEV: {len(catalog['vulnerabilities'])} vulnerabilities")

    kev_ids = [row.get("cveID") for row in catalog.get("vulnerabilities", []) if row.get("cveID")]
    frontier = safe_fetch(fetch_epss_frontier, kev_ids) or {}
    if frontier.get("rows"):
        live["epss_frontier"] = frontier
        print(f"  FIRST EPSS frontier: {len(frontier['rows'])} CVEs")

    articles = safe_fetch(fetch_google_news_rss, query, SNAPSHOT_SIZE) or []
    if articles:
        live["news_articles"] = articles[:SNAPSHOT_SIZE]
        print(f"  News RSS: {len(articles)} articles")

    return live


def retain_previous(live, previous):
    notes = []
    previous_live = previous.get("live_data") or {}
    try:
        generated = datetime.fromisoformat(str(previous.get("meta", {}).get("generated", "")).replace("Z", "+00:00"))
        if generated.tzinfo is None:
            generated = generated.replace(tzinfo=timezone.utc)
        previous_fresh = 0 <= (datetime.now(timezone.utc) - generated).total_seconds() <= 72 * 3600
    except ValueError:
        previous_fresh = False
    limits = {"news_articles": SNAPSHOT_SIZE, "cisa_catalog": None, "epss_frontier": None}
    for key, limit in limits.items():
        if live.get(key) or not previous_fresh or not previous_live.get(key):
            continue
        retained = previous_live[key]
        if isinstance(retained, list) and limit:
            retained = retained[:limit]
        elif isinstance(retained, dict):
            retained = dict(retained)
            retained["retained"] = True
        live[key] = retained
        notes.append(f"{key} unavailable; retained a validated snapshot less than 72 hours old.")
        print(f"  {key}: retained from previous run")
    for key in ("cisa_catalog", "epss_frontier"):
        if (live.get(key) or {}).get("cached"):
            notes.append(f"{key} endpoint unavailable; used verified cache less than 72 hours old.")
    return notes


def build_stats(articles, feeds):
    domains = len({a.get("domain") for a in articles if a.get("domain")})
    tones = [float(a.get("tone")) for a in articles if isinstance(a.get("tone"), (int, float))]
    mean_tone = sum(tones) / len(tones) if tones else 0.0
    tone_index = round(max(0, min(100, 50 + mean_tone * 5)))
    direction = "positive" if mean_tone > 0.2 else ("negative" if mean_tone < -0.2 else "neutral")
    return [
        {"label": "Articles Tracked", "value": str(len(articles)), "delta": "live" if articles else "none"},
        {"label": "News Domains", "value": str(domains), "delta": "deduplicated"},
        {"label": "Tone Index", "value": f"{tone_index}/100 ({direction})", "delta": "news scale"},
        {"label": "Live Feeds", "value": str(feeds), "delta": "connected"},
    ]


def main():
    config = load_config()
    project = (config.get("project") or {}).get("id", "unknown-project")
    title = (config.get("project") or {}).get("name", project)
    print(f"=== {title} pipeline ===")

    previous = load_previous()
    live = extract_live_data(config)
    notes = retain_previous(live, previous)

    articles = live.get("news_articles", [])
    catalog = live.get("cisa_catalog") or {}
    frontier = live.get("epss_frontier") or {}
    official_available = bool(catalog.get("vulnerabilities")) or bool(frontier.get("rows"))
    if not official_available:
        print("[ERROR] No current or valid retained CISA/EPSS data; preserving last-good output")
        return False
    degraded = bool(notes) or not articles or not catalog.get("vulnerabilities") or not frontier.get("rows")
    mode = "partial" if degraded else "live"

    llm_summary = ""
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if api_key and articles:
        print("[LLM] Analyzing with OpenRouter...")
        llm_summary = analyze_with_llm(
            {
                "meta": {"project": project, "mode": mode},
                "events": articles[:5],
                "stats": build_stats(articles, len(live)),
            },
            config.get("openrouter"),
            api_key,
        )
        if llm_summary:
            print("[LLM] Summary received")

    output = {
        "meta": {
            "project": project,
            "generated": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "sources": [key for key, value in live.items() if value],
            "source_notes": notes,
            "version": "2.0.0",
        },
        "stats": build_stats(articles, len(live)),
        "live_data": live,
        "entities": [],
        "events": articles[:EVENT_LIMIT],
        "timeseries": [],
        "llm_summary": llm_summary,
        "early_warning": build_cyber_warning(
            catalog,
            frontier,
            articles,
            previous=previous.get("early_warning") or {},
        ),
    }

    os.makedirs("data", exist_ok=True)
    out_path = os.path.join("data", "output.json")
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, ensure_ascii=False)

    size = os.path.getsize(out_path)
    print(f"Done. {out_path} ({size} bytes) mode={mode} articles={len(articles)}")
    return True


if __name__ == "__main__":
    raise SystemExit(0 if main() else 2)
