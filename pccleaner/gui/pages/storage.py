"""Armazenamento: gráficos de barras por categoria, app, pastas, crescimento e arquivos antigos."""
from __future__ import annotations

import logging
import os
from collections import defaultdict

from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QWidget

from pccleaner.core.models import ScanResult
from pccleaner.gui.pages import Page, scrollable
from pccleaner.gui.state import AppState
from pccleaner.gui.utils import fmt_dt, fmt_size, value_bytes
from pccleaner.gui.widgets import Card, HBarChart, make_label
from pccleaner.workers import FunctionWorker

log = logging.getLogger(__name__)


def _local_summary(result: ScanResult) -> dict:
    """Resumo mínimo calculado localmente caso analyzer.summarize falhe."""
    by_cat: dict[str, int] = defaultdict(int)
    by_app: dict[str, int] = defaultdict(int)
    for f in result.findings:
        by_cat[f.category.value] += f.size_bytes
        by_app[f.app or "Outros"] += f.size_bytes
    return {"by_category": dict(by_cat), "by_app": dict(by_app), "recent_growth": [],
            "old_large_files": [], "recoverable_bytes": result.recoverable_bytes}


def summarize_result(result: ScanResult) -> dict:
    try:
        from pccleaner.analyzer import summarize
        return summarize(result)
    except Exception as exc:  # noqa: BLE001
        log.info("analyzer.summarize indisponível (%s); usando resumo local", exc)
        return _local_summary(result)


def _short(path: str) -> str:
    parts = path.rstrip("\\/").split(os.sep)
    return os.sep.join(parts[-2:]) if len(parts) > 2 else path


def _dict_rows(d) -> list[tuple]:
    if isinstance(d, dict):
        return [(str(k), value_bytes(v)) for k, v in d.items()]
    rows = []
    for x in d or []:
        if isinstance(x, (list, tuple)) and len(x) >= 2:
            rows.append((str(x[0]), value_bytes(x[1])))
        elif isinstance(x, dict):
            rows.append((str(x.get("name") or x.get("label") or x.get("category") or x.get("app")),
                         value_bytes(x)))
    return rows


class StoragePage(Page):
    title = "Armazenamento"

    def __init__(self, state: AppState, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state
        self._worker = None
        head = QHBoxLayout()
        head.addWidget(make_label("Armazenamento", "h1"))
        head.addStretch(1)
        self.lbl = make_label("Execute uma análise para ver os gráficos.", "muted")
        head.addWidget(self.lbl)
        self.root.addLayout(head)
        inner = QWidget()
        grid = QGridLayout(inner)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(12)
        self.ch_cat = HBarChart("Por categoria")
        self.ch_app = HBarChart("Por aplicativo")
        self.ch_top = HBarChart("Maiores pastas", max_rows=20)
        self.ch_growth = HBarChart("Crescimento recente (modificadas nos últimos dias)")
        self.ch_old = HBarChart("Arquivos grandes e antigos", max_rows=20)
        self.charts = (self.ch_cat, self.ch_app, self.ch_top, self.ch_growth, self.ch_old)
        for i, ch in enumerate(self.charts):
            card = Card()
            card.lay.addWidget(ch)
            card.lay.addStretch(1)
            if i < 2:
                grid.addWidget(card, 0, i)
            else:
                grid.addWidget(card, i - 1, 0, 1, 2)
        grid.setRowStretch(5, 1)
        self.root.addWidget(scrollable(inner), 1)
        state.resultChanged.connect(self.set_result)
        state.cleanFinished.connect(lambda _r: self.set_result(self.state.result))

    def set_result(self, result: ScanResult | None) -> None:
        if result is None:
            for ch in self.charts:
                ch.set_data([])
            return
        self.lbl.setText("Calculando…")
        w = FunctionWorker(summarize_result, result)
        w.finished.connect(lambda s, r=result: self.show_summary(r, s))
        w.error.connect(lambda m: self.lbl.setText(f"Erro: {m}"))
        self._worker = w
        w.start()

    def show_summary(self, result: ScanResult, s: dict) -> None:
        s = s or {}
        self.ch_cat.set_data(_dict_rows(s.get("by_category", {})))
        self.ch_app.set_data(_dict_rows(s.get("by_app", {})))
        self.ch_top.set_data([(_short(f.path), f.size_bytes, f.path) for f in result.top_folders])
        self.ch_growth.set_data([(_short(f.path), f.size_bytes, f"{f.path}\nModificada: {fmt_dt(f.newest_mtime)}")
                                 for f in s.get("recent_growth") or []])
        self.ch_old.set_data([(os.path.basename(f.path), f.size_bytes,
                               f"{f.path}\nÚltima modificação: {fmt_dt(f.mtime)}")
                              for f in s.get("old_large_files") or []])
        rec = s.get("recoverable_bytes", result.recoverable_bytes)
        self.lbl.setText(f"Recuperável: {fmt_size(rec)} · {len(result.top_folders)} pastas mapeadas")
