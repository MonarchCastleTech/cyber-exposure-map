# Cyber Threat Exposure Map

[![Pages](https://github.com/MonarchCastleTech/cyber-exposure-map/actions/workflows/pipeline.yml/badge.svg)](https://github.com/MonarchCastleTech/cyber-exposure-map/actions/workflows/pipeline.yml)

Autonomous global cyber-exploitation pressure warning built from CISA KEV,
FIRST EPSS, and independent public precursor reporting.

**Live dashboard:** https://monarchcastletech.github.io/cyber-exposure-map/

## Run locally

```bash
python -m pip install -r requirements.txt
python pipeline/cyber_exposure_map_pipeline.py
python -m http.server 8000
```

Open `http://localhost:8000`. Direct `file://` access cannot fetch `data/output.json` in modern browsers.

## Automation

GitHub Actions refreshes public data every six hours and deploys the static dashboard to GitHub Pages. AI briefs are optional: configure `OPENROUTER_API_KEY` as a repository Actions secret. Without it, core collection and dashboard deployment remain available.

The deterministic warning model never requires an API key. CISA and EPSS
snapshots are cached for at most 72 hours; expired fallback data is rejected.
The workflow preserves the last accepted publication when both official feeds
are unavailable.

## Warning methodology

- **40% CISA KEV addition pressure:** current seven-day additions versus 26
  prior non-overlapping weeks using a median/MAD robust z-score.
- **35% EPSS frontier momentum:** highest EPSS CVEs above 0.10 that are not yet
  in KEV, scored on current probability and seven-day acceleration.
- **25% cross-source precursor language:** independent-source confirmation of
  weaponization, mass scanning, perimeter access, and campaign-shift phrases.

Available weights are renormalized. A disclosed five-point bonus applies only
when at least two components reach WATCH. The result is global analyst-triage
pressure for the next 30 days, not an organisation-specific breach probability.

Primary references: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
[FIRST EPSS API](https://api.first.org/epss/), and
[EPSS research](https://www.first.org/epss/research.html).

## Data notice

Source availability varies. The dashboard identifies its generation time and operating mode in `data/output.json`. Treat indicators as decision-support signals, not verified ground truth.

## Brand

Part of Monarch Castle Technologies. See [BRAND.md](BRAND.md) for approved asset use.
