from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_ui_discloses_warning_method_and_real_sources():
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    script = (ROOT / "assets" / "app.js").read_text(encoding="utf-8")
    assert "Cyber Exploitation Early Warning" in html
    assert "Methodology" in html
    assert "CISA KEV" in html
    assert "FIRST EPSS" in html
    assert "AlienVault OTX" not in html
    assert "Shodan" not in html
    assert "renderEarlyWarning" in script
    assert "global exploitation pressure" in html.lower()


def test_workflow_runs_tests_and_preserves_last_good_data():
    workflow = (ROOT / ".github" / "workflows" / "pipeline.yml").read_text(encoding="utf-8")
    assert "python -m pytest -q" in workflow
    assert "actions/cache@v6" in workflow
    assert "set -euo pipefail" in workflow
    assert "continue-on-error: true" in workflow
    assert "Retry delayed Pages activation" in workflow

