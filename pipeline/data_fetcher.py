# -*- coding: utf-8 -*-
"""Shared data fetchers for MCT Intelligence projects."""
import os
import json
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path

CACHE_MAX_AGE = timedelta(hours=72)


def _cache_path(name):
    root = Path(os.path.expanduser("~")) / ".cache" / "cyber-exposure-map"
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{name}.json"


def _read_recent_cache(name):
    path = _cache_path(name)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        fetched = datetime.fromisoformat(str(payload.get("fetched_at", "")).replace("Z", "+00:00"))
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - fetched.astimezone(timezone.utc)
        if timedelta(0) <= age <= CACHE_MAX_AGE:
            return payload.get("data")
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return None


def _write_cache(name, data):
    _cache_path(name).write_text(
        json.dumps({"fetched_at": datetime.now(timezone.utc).isoformat(), "data": data}),
        encoding="utf-8",
    )

def fetch_nasa_firms(api_key=None, region="world", days=1):
    """Fetch NASA FIRMS fire/thermal anomaly data."""
    key = api_key or os.environ.get("NASA_FIRMS_API_KEY", "")
    if not key:
        return []
    url = f"https://firms.modaps.eosdis.nasa.gov/api/area/csv/{key}/VIIRS_SNPP_NPP/{region}/{days}"
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            lines = r.text.strip().split("\n")
            if len(lines) < 2:
                return []
            headers = lines[0].split(",")
            return [
                dict(zip(headers, line.split(",")))
                for line in lines[1:]
                if line.strip()
            ][:500]
        return []
    except Exception as e:
        print(f"[NASA-FIRMS] Error: {e}")
        return []

def fetch_cisa_kev():
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        r = requests.get(url, timeout=30, headers={"User-Agent": "MCT-Intel/1.0"})
        if r.status_code == 200:
            raw = r.json()
            data = {
                "catalog_version": raw.get("catalogVersion"),
                "date_released": raw.get("dateReleased"),
                "vulnerabilities": [
                    {
                        "cveID": v.get("cveID", ""),
                        "vendorProject": v.get("vendorProject", ""),
                        "product": v.get("product", ""),
                        "vulnerabilityName": v.get("vulnerabilityName", ""),
                        "dateAdded": v.get("dateAdded", ""),
                        "shortDescription": v.get("shortDescription", ""),
                        "requiredAction": v.get("requiredAction", ""),
                        "dueDate": v.get("dueDate", ""),
                        "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse", "Unknown"),
                        "notes": v.get("notes", ""),
                        "cwes": v.get("cwes", []),
                        "source": "CISA-KEV",
                    }
                    for v in raw.get("vulnerabilities", [])
                ],
                "cached": False,
            }
            if data["vulnerabilities"]:
                _write_cache("cisa-kev", data)
                return data
        cached = _read_recent_cache("cisa-kev")
        if cached:
            cached["cached"] = True
            return cached
        return {}
    except Exception as e:
        print(f"[CISA-KEV] Error: {e}")
        cached = _read_recent_cache("cisa-kev")
        if cached:
            cached["cached"] = True
            return cached
        return {}


def fetch_epss_frontier(kev_ids, threshold=0.10, candidate_limit=40):
    """Fetch high-EPSS non-KEV CVEs and their public 30-day time series."""
    url = "https://api.first.org/data/v1/epss"
    headers = {"User-Agent": "cyber-exposure-map/2.0"}
    try:
        rows = []
        offset = 0
        total = None
        while total is None or offset < total:
            response = requests.get(
                url,
                params={"epss-gt": threshold, "limit": 10000, "offset": offset},
                timeout=35,
                headers=headers,
            )
            response.raise_for_status()
            payload = response.json()
            page = payload.get("data") or []
            rows.extend(page)
            total = int(payload.get("total") or len(rows))
            if not page:
                break
            offset += len(page)

        kev_set = {str(value).upper() for value in kev_ids}
        frontier = sorted(
            (row for row in rows if str(row.get("cve") or "").upper() not in kev_set),
            key=lambda row: float(row.get("epss") or 0),
            reverse=True,
        )[:candidate_limit]
        if frontier:
            identifiers = ",".join(str(row["cve"]) for row in frontier)
            history_response = requests.get(
                url,
                params={"cve": identifiers, "scope": "time-series", "limit": candidate_limit},
                timeout=35,
                headers=headers,
            )
            history_response.raise_for_status()
            history = {row.get("cve"): row for row in history_response.json().get("data") or []}
            for row in frontier:
                series = history.get(row.get("cve"), {}).get("time-series") or []
                row["time_series"] = series

        data = {
            "threshold": threshold,
            "total_above_threshold": total or 0,
            "rows": frontier,
            "cached": False,
        }
        if frontier:
            _write_cache("epss-frontier", data)
            return data
    except Exception as e:
        print(f"[FIRST-EPSS] Error: {e}")
    cached = _read_recent_cache("epss-frontier")
    if cached:
        cached["cached"] = True
        return cached
    return {}

def fetch_acled(*_args, **_kwargs):
    """Disabled until a licensed ACLED key is explicitly configured."""
    return []

def fetch_opensanctions(*_args, **_kwargs):
    """Disabled: current OpenSanctions API requires authenticated access."""
    return {}

def fetch_census_country():
    """Fetch World Bank country indicators (GDP, population)."""
    url = "https://api.worldbank.org/v2/country?format=json&per_page=300"
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            data = r.json()
            if len(data) > 1:
                return [
                    {
                        "id": c.get("id", ""),
                        "name": c.get("name", ""),
                        "region": c.get("region", {}).get("value", ""),
                        "capitalCity": c.get("capitalCity", ""),
                        "longitude": c.get("longitude", ""),
                        "latitude": c.get("latitude", ""),
                    }
                    for c in data[1]
                ]
        return []
    except Exception as e:
        print(f"[WorldBank] Error: {e}")
        return []

def fetch_coingecko(coin="bitcoin"):
    """Fetch crypto market data from CoinGecko (free, no key)."""
    url = f"https://api.coingecko.com/api/v3/coins/{coin}"
    try:
        r = requests.get(url, params={"localization": "false", "tickers": "false"}, timeout=30)
        return r.json() if r.status_code == 200 else {}
    except Exception as e:
        print(f"[CoinGecko] Error: {e}")
        return {}

def fetch_exchange_rates(base="USD"):
    """Fetch free exchange rates (no key needed)."""
    url = f"https://api.exchangerate-api.com/v4/latest/{base}"
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            data = r.json()
            rates = data.get("rates", {})
            # Return top 20 rates as list of dicts
            return [{"currency": k, "rate": v} for k, v in list(rates.items())[:20]]
        return []
    except Exception as e:
        print(f"[ExchangeRate] Error: {e}")
        return []

def fetch_weather(lat, lon):
    """Fetch free weather from Open-Meteo (no key)."""
    url = "https://api.open-meteo.com/v1/forecast"
    params = {"latitude": lat, "longitude": lon, "current": "temperature_2m,wind_speed_10m"}
    try:
        r = requests.get(url, params=params, timeout=30)
        return r.json() if r.status_code == 200 else {}
    except Exception as e:
        print(f"[OpenMeteo] Error: {e}")
        return {}

def fetch_covid_global():
    """Fetch COVID-19 summary data."""
    url = "https://disease.sh/v3/covid-19/countries"
    try:
        r = requests.get(url, timeout=30)
        return r.json() if r.status_code == 200 else []
    except Exception as e:
        print(f"[COVID] Error: {e}")
        return []

def fetch_earthquakes(hours=24):
    """Fetch recent earthquake data from USGS."""
    url = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson"
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            data = r.json()
            features = data.get("features", [])
            return [
                {
                    "place": f.get("properties", {}).get("place", ""),
                    "mag": f.get("properties", {}).get("mag", 0),
                    "time": f.get("properties", {}).get("time", ""),
                    "lon": f.get("geometry", {}).get("coordinates", [0, 0, 0])[0],
                    "lat": f.get("geometry", {}).get("coordinates", [0, 0, 0])[1],
                    "depth": f.get("geometry", {}).get("coordinates", [0, 0, 0])[2],
                    "source": "USGS"
                }
                for f in features[:200]
            ]
        return []
    except Exception as e:
        print(f"[USGS-Quake] Error: {e}")
        return []

def safe_fetch(fetcher, *args, **kwargs):
    """Wrapper that catches all exceptions and returns empty data."""
    try:
        return fetcher(*args, **kwargs)
    except Exception as e:
        print(f"[SafeFetch] {fetcher.__name__} failed: {e}")
        return {} if not isinstance(args, list) else []

def fetch_google_news_rss(query, max_results=50):
    """Fetch news headlines from Google News RSS."""
    import re
    import urllib.parse
    import xml.etree.ElementTree as ET
    from datetime import datetime, timezone

    url = (
        "https://news.google.com/rss/search?q="
        + urllib.parse.quote(query)
        + "&hl=en-US&gl=US&ceid=US:en"
    )
    try:
        r = requests.get(url, timeout=30, headers={"User-Agent": "MCT-Intel/1.0"})
        if r.status_code != 200:
            print(f"[GoogleNews] HTTP {r.status_code}")
            return []
        root = ET.fromstring(r.content)
        items = root.findall(".//item")[:max_results]
        articles = []
        for item in items:
            title = (item.findtext("title") or "").strip()
            link = item.findtext("link") or ""
            pub = item.findtext("pubDate") or ""
            source_el = item.find("source")
            source_name = source_el.text.strip() if source_el is not None and source_el.text else ""
            if source_name and title.endswith(" - " + source_name):
                title = title[: -(len(source_name) + 3)].strip()
            seendate = ""
            for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%a, %d %b %Y %H:%M:%S %z"):
                try:
                    dt = datetime.strptime(pub.replace("GMT", "UTC"), fmt)
                    seendate = dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                    break
                except ValueError:
                    continue
            if not seendate:
                seendate = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            domain = re.sub(r"[^a-z0-9.-]", "", (source_name or "news.google.com").lower()) or "news.google.com"
            articles.append({
                "title": title,
                "url": link,
                "domain": domain,
                "language": "",
                "tone": 0,
                "seendate": seendate,
                "source": "GoogleNews",
            })
        return articles
    except Exception as e:
        print(f"[GoogleNews] Error: {e}")
        return []
