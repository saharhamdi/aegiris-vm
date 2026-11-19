from datetime import datetime

from app.scoring import (
    cvss_to_severity,
    due_date_for,
    priority_from_score,
    risk_score,
    severity_to_cvss,
)


def test_score_is_bounded():
    assert 0 <= risk_score(10, 1, True, 5) <= 100
    assert risk_score(0, 0, False, 1) == 0


def test_kev_raises_priority():
    without = risk_score(7.5, 0.1, False, 3)
    with_kev = risk_score(7.5, 0.1, True, 3)
    assert with_kev > without
    assert priority_from_score(with_kev) in ("High", "Critical")


def test_asset_criticality_raises_score():
    low = risk_score(6.0, 0.05, False, 1)
    high = risk_score(6.0, 0.05, False, 5)
    assert high > low


def test_epss_raises_score():
    assert risk_score(6.0, 0.9, False, 3) > risk_score(6.0, 0.01, False, 3)


def test_priority_thresholds():
    assert priority_from_score(85) == "Critical"
    assert priority_from_score(65) == "High"
    assert priority_from_score(45) == "Medium"
    assert priority_from_score(10) == "Low"


def test_sla_depends_on_priority():
    start = datetime(2026, 1, 1)
    assert (due_date_for("Critical", start) - start).days == 7
    assert (due_date_for("Low", start) - start).days == 180


def test_severity_mappings():
    assert cvss_to_severity(9.8) == "critical"
    assert cvss_to_severity(0) == "info"
    assert severity_to_cvss("HIGH") == 8.0
    assert severity_to_cvss(None) == 5.0
