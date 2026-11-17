from __future__ import annotations

import csv
import json
import time

from pccleaner.analyzer import list_drives, summarize
from pccleaner.core.models import (Category, CleanItemResult, CleanMode, CleanReport, Finding, FolderStat,
                                   LargeFile, SafetyLevel, ScanResult)
from pccleaner.reporting import export_report


def _result() -> ScanResult:
    t = time.time()
    fs = [Finding(id=f"f{i}", rule_id="r", name=n, path=f"X:\\a\\{i}", category=c, app=a, safety=sl,
                  reason="motivo", recommendation="rec", clean_mode=CleanMode.CONTENTS, size_bytes=sz)
          for i, (n, c, a, sl, sz) in enumerate([
              ("Cache <b>", Category.BROWSER_CACHE, "Chrome", SafetyLevel.SAFE, 5000),
              ("Logs", Category.SYSTEM_LOGS, "Windows", SafetyLevel.REVIEW, 1000),
              ("Deps", Category.DEV_DEPENDENCIES, "Node", SafetyLevel.CAUTION, 9000)])]
    return ScanResult("s1", t - 3, t, fs,
                      [FolderStat("X:\\new", 10, 1, t - 86400), FolderStat("X:\\old", 9, 1, t - 400 * 86400)],
                      [LargeFile("X:\\old.iso", 100, t - 800 * 86400), LargeFile("X:\\new.iso", 90, t)],
                      100, 10_000, ["aviso"])


def test_summarize():
    s = summarize(_result())
    assert s["recoverable_bytes"] == 6000
    assert s["by_safety"]["seguro"] == 5000 and list(s["by_category"])[0] == Category.DEV_DEPENDENCIES.value
    assert [f.path for f in s["recent_growth"]] == ["X:\\new"]
    assert [f.path for f in s["old_large_files"]] == ["X:\\old.iso"]


def test_exports(tmp_path):
    r = _result()
    cr = CleanReport(time.time(), time.time(), [CleanItemResult("f0", "X:\\a\\0", 5000, 2)])
    pj = export_report(r, str(tmp_path / "rel"), "json", cr)
    data = json.loads(open(pj, encoding="utf-8").read())
    assert len(data["findings"]) == 3 and data["clean"]["freed_bytes"] == 5000
    pc = export_report(r, str(tmp_path / "rel.csv"), "csv")
    rows = list(csv.reader(open(pc, encoding="utf-8-sig"), delimiter=";"))
    assert rows[0][0] == "nome" and len(rows) == 4
    ph = export_report(r, str(tmp_path / "rel"), "html", cr)
    h = open(ph, encoding="utf-8").read()
    assert h.startswith("<!doctype html>") and "Cache &lt;b&gt;" in h and "Resultado da limpeza" in h


def test_list_drives_readonly():
    for d in list_drives():
        assert d["total"] >= d["free"] >= 0
