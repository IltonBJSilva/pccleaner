from __future__ import annotations

import time

from pccleaner.core.models import (Category, CleanItemResult, CleanMode, CleanReport, Finding, SafetyLevel,
                                   ScanResult)
from pccleaner.database import HistoryDB


def test_roundtrip(tmp_path):
    db = HistoryDB(tmp_path / "h.sqlite3")
    t = time.time()
    f = Finding(id="f1", rule_id="r", name="Cache", path="X:\\a\\b", category=Category.APP_CACHE, app="A",
                safety=SafetyLevel.SAFE, reason="", recommendation="", clean_mode=CleanMode.CONTENTS, size_bytes=500)
    db.save_scan(ScanResult("s1", t - 5, t, [f], [], [], 10, 1000, []))
    db.save_scan(ScanResult("s1", t - 5, t, [f], [], [], 10, 1000, []))   # idempotente
    (row,) = db.list_scans()
    assert row["scan_id"] == "s1" and row["findings"] == 1 and row["recoverable_bytes"] == 500
    assert db.last_scan()["scan_id"] == "s1"
    rep = CleanReport(t, t + 1, [CleanItemResult("f1", "X:\\a\\b", 400, 3, 1, True, ["e1", "e2"])])
    cid = db.save_clean(rep, "s1")
    (c,) = db.list_cleans()
    assert c["id"] == cid and c["freed_bytes"] == 400 and c["files_removed"] == 3 and c["errors"] == 2
    (item,) = db.clean_items(cid)
    assert item["quarantined"] is True and item["errors"] == "e1\ne2"
