"""Smoke tests da GUI (offscreen). Não apagam nada e não dependem dos módulos de backend."""
from __future__ import annotations

import os
import sys
import time
import types

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PySide6.QtCore import QEventLoop, Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from pccleaner.core.models import (Category, CleanMode, Finding, SafetyLevel,  # noqa: E402
                                   ScanOptions, ScanProgress, ScanResult)


@pytest.fixture(scope="session")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))


def fake_findings(n: int) -> list[Finding]:
    cats, levels = list(Category), list(SafetyLevel)
    out = []
    for i in range(n):
        safety = levels[i % len(levels)]
        path = rf"C:\Fake\dir{i}\cache"
        out.append(Finding(
            id=Finding.make_id(path, "r"), rule_id="r", name=f"item{i}", path=path,
            category=cats[i % len(cats)], app=f"App{i % 7}", safety=safety, reason="motivo",
            recommendation="recomendação",
            clean_mode=CleanMode.NONE if safety is SafetyLevel.PROTECTED else CleanMode.CONTENTS,
            size_bytes=(i * 7919) % 10_000_000, file_count=i % 100, last_modified=time.time() - i,
            requires_admin=(i % 13 == 0), command_hint="pip cache purge" if i % 5 == 0 else "",
            notes=["nota"] if i % 3 == 0 else []))
    return out


def fake_result(findings: list[Finding]) -> ScanResult:
    return ScanResult(scan_id="t", started_at=time.time() - 5, finished_at=time.time(),
                      findings=findings, top_folders=[], large_files=[], files_scanned=1234,
                      bytes_scanned=10 ** 9, errors=[])


def wait_until(pred, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        QApplication.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)
        if pred():
            return True
        time.sleep(0.01)
    return pred()


def test_import_app():
    import pccleaner.gui.app  # noqa: F401
    import pccleaner.workers  # noqa: F401


def test_main_window_with_results(qapp):
    from pccleaner.gui import theme
    from pccleaner.gui.main_window import MainWindow
    from pccleaner.gui.results_model import COL_CHECK, COL_SIZE, SORT_ROLE

    qapp.setStyleSheet(theme.stylesheet("dark"))
    win = MainWindow(auto_refresh=False)
    win.show()
    findings = fake_findings(10_000)
    t0 = time.perf_counter()
    win.state.set_result(fake_result(findings))
    page = win.pages["results"]
    assert page.model.rowCount() == 10_000 == page.proxy.rowCount()

    page.view.sortByColumn(COL_SIZE, Qt.SortOrder.DescendingOrder)
    sizes = [page.proxy.index(r, COL_SIZE).data(SORT_ROLE) for r in range(50)]
    assert sizes == sorted(sizes, reverse=True)

    page.proxy.set_safety(SafetyLevel.SAFE)
    assert page.proxy.rowCount() == 2500
    page.select_all_safe()
    count, size = page.model.selection_stats()
    assert count == 2500
    assert size == sum(f.size_bytes for f in findings if f.safety is SafetyLevel.SAFE)  # > 2^31 ok
    page.model.clear_selection()
    assert page.model.selection_stats() == (0, 0)
    page.proxy.set_safety(None)
    page.proxy.set_text("item123")
    assert page.proxy.rowCount() >= 1
    page.proxy.set_text("")
    assert time.perf_counter() - t0 < 20

    prot_row = next(i for i, f in enumerate(findings) if f.safety is SafetyLevel.PROTECTED)
    idx = page.model.index(prot_row, COL_CHECK)
    assert not (page.model.flags(idx) & Qt.ItemFlag.ItemIsUserCheckable)
    assert not page.model.setData(idx, Qt.CheckState.Checked, Qt.ItemDataRole.CheckStateRole)
    ok_row = next(i for i, f in enumerate(findings) if f.cleanable)
    assert page.model.setData(page.model.index(ok_row, COL_CHECK), Qt.CheckState.Checked.value,
                              Qt.ItemDataRole.CheckStateRole)
    assert page.model.selection_stats()[0] == 1
    assert page.model.selected_findings() == [findings[ok_row]]
    assert page.btn_clean.isEnabled()

    page.detail.show_finding(findings[0])
    assert findings[0].path in page.detail.lbl_path.text()

    for key in ("dashboard", "scan", "results", "storage", "duplicates", "settings"):
        win.go(key)
        qapp.processEvents()
        assert not win.grab().isNull()
    win.close()


def test_storage_charts(qapp):
    from pccleaner.gui.pages.storage import StoragePage, _local_summary
    from pccleaner.gui.state import AppState

    page = StoragePage(AppState())
    res = fake_result(fake_findings(200))
    page.show_summary(res, _local_summary(res))
    assert page.ch_cat.data and page.ch_app.data
    page.resize(900, 700)
    assert not page.grab().isNull()


def test_duplicates_keep_one(qapp, tmp_path, monkeypatch):
    from pccleaner.gui.pages import duplicates
    from pccleaner.gui.state import AppState

    monkeypatch.setattr(duplicates, "refusal_reason", lambda p: None)

    class G:
        def __init__(self, paths):
            self.sha256, self.size_bytes, self.paths = "a" * 64, 10, paths
            self.wasted_bytes = 10 * (len(paths) - 1)

    paths = []
    for i in range(3):
        p = tmp_path / f"f{i}.bin"
        p.write_bytes(b"x" * 10)
        paths.append(str(p))
    page = duplicates.DuplicatesPage(AppState())
    page.set_groups([G(paths)])
    top = page.tree.topLevelItem(0)
    for i in range(3):
        top.child(i).setCheckState(0, Qt.CheckState.Checked)
    assert len(page.selected()) == 2  # a última cópia nunca pode ser marcada
    f = duplicates.make_duplicate_finding(paths[0], 10)
    assert f.category is Category.DUPLICATES and f.clean_mode is CleanMode.WHOLE
    assert f.safety is SafetyLevel.REVIEW and f.cleanable and f.selected


def test_confirm_dialog_flags_refused(qapp):
    from pccleaner.config import Settings
    from pccleaner.gui.dialogs import CleanConfirmDialog

    items = fake_findings(50)
    for f in items:
        f.selected = f.cleanable
    items[1].selected = False                     # não selecionado: nunca listado
    root = Finding(id="root", rule_id="r", name="raiz", path="C:\\", category=Category.OTHER, app="",
                   safety=SafetyLevel.SAFE, reason="", recommendation="", clean_mode=CleanMode.CONTENTS,
                   selected=True)
    prot = items[3]                               # PROTECTED (índice 3)
    prot.selected = True
    dlg = CleanConfirmDialog(items + [root], Settings())
    refused = {f.id for f, _ in dlg.refused}
    assert "root" in refused and prot.id in refused
    assert all(f.cleanable and f.selected for f in dlg.findings)
    assert items[1] not in dlg.findings and root not in dlg.findings
    assert not dlg.btn_ok.isEnabled()
    dlg.chk_confirm.setChecked(True)
    assert dlg.btn_ok.isEnabled()
    dlg.close()


def test_clean_worker_only_selected():
    from pccleaner.workers import CleanWorker

    items = fake_findings(20)
    for i, f in enumerate(items):
        f.selected = i % 2 == 0
    w = CleanWorker(items)
    assert w.findings and all(f.selected and f.cleanable for f in w.findings)


def test_function_worker_roundtrip(qapp):
    from pccleaner.workers import FunctionWorker

    got, errs = [], []
    w = FunctionWorker(lambda a, b: a + b, 2, 3)
    w.finished.connect(got.append)
    w.start()
    assert wait_until(lambda: got == [5])
    w.wait(2000)
    w2 = FunctionWorker(lambda: 1 / 0)
    w2.error.connect(errs.append)
    w2.start()
    assert wait_until(lambda: bool(errs)) and "ZeroDivisionError" in errs[0]
    w2.wait(2000)


def test_scan_flow_with_fake_backend(qapp, monkeypatch):
    """ScanWorker -> ScanPage -> MainWindow -> Resultados, com scanner falso (nada é apagado)."""
    from pccleaner.gui.main_window import MainWindow

    findings = fake_findings(300)

    def run_scan(options, progress=None, cancel=None):
        for i in range(20):
            if progress:
                progress(ScanProgress(phase="Teste", current_path=rf"C:\x\{i}", files_scanned=i,
                                      bytes_scanned=i * 1000, findings_count=i,
                                      categories={"Cache de navegador": i}, percent=i * 5))
            time.sleep(0.005)
        return fake_result(findings)

    fake = types.ModuleType("pccleaner.scanner")
    fake.run_scan = run_scan
    monkeypatch.setitem(sys.modules, "pccleaner.scanner", fake)
    monkeypatch.setitem(sys.modules, "pccleaner.database", types.ModuleType("pccleaner.database"))

    win = MainWindow(auto_refresh=False)
    win.start_scan(ScanOptions(roots=[r"C:\x"]))
    assert wait_until(lambda: win.state.result is not None, 10)
    assert win.pages["results"].model.rowCount() == 300
    assert win.stack.currentWidget() is win.pages["results"]
    win.close()
