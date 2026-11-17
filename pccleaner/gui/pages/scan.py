"""Análise em tempo real."""
from __future__ import annotations

import time

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import QHBoxLayout, QListWidget, QProgressBar, QPushButton, QWidget

from pccleaner.core.models import ScanOptions, ScanProgress
from pccleaner.gui.pages import Page
from pccleaner.gui.utils import fmt_duration, fmt_int, fmt_size
from pccleaner.gui.widgets import Card, StatCard, make_label
from pccleaner.workers import ScanWorker


class ScanPage(Page):
    title = "Análise"
    scanFinished = Signal(object)   # ScanResult
    scanFailed = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.worker: ScanWorker | None = None
        self._t0 = 0.0
        head = QHBoxLayout()
        head.addWidget(make_label("Análise", "h1"))
        head.addStretch(1)
        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.setObjectName("danger")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self.cancel)
        head.addWidget(self.btn_cancel)
        self.root.addLayout(head)

        self.lbl_phase = make_label("Nenhuma análise em andamento.", "h2")
        self.root.addWidget(self.lbl_phase)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        self.root.addWidget(self.bar)
        self.lbl_path = make_label("", "muted")
        self.lbl_path.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.root.addWidget(self.lbl_path)

        stats = QHBoxLayout()
        self.c_files = StatCard("Arquivos analisados", "0")
        self.c_bytes = StatCard("Volume analisado", "0 B")
        self.c_findings = StatCard("Oportunidades", "0")
        self.c_time = StatCard("Tempo decorrido", "00m 00s")
        self.c_errors = StatCard("Sem acesso", "0")
        for c in (self.c_files, self.c_bytes, self.c_findings, self.c_time, self.c_errors):
            stats.addWidget(c)
        self.root.addLayout(stats)

        card = Card()
        card.lay.addWidget(make_label("Categorias encontradas", "h2"))
        self.cats = QListWidget()
        card.lay.addWidget(self.cats)
        self.root.addWidget(card, 1)

        self.timer = QTimer(self)
        self.timer.setInterval(500)
        self.timer.timeout.connect(self._tick)

    def is_running(self) -> bool:
        return self.worker is not None and self.worker.is_running()

    def start(self, options: ScanOptions) -> None:
        if self.is_running():
            return
        self.cats.clear()
        for c, v in ((self.c_files, "0"), (self.c_bytes, "0 B"), (self.c_findings, "0"),
                     (self.c_time, "00m 00s"), (self.c_errors, "0")):
            c.set(v)
        self.lbl_path.setText("")
        self._t0 = time.monotonic()
        self.lbl_phase.setText("Iniciando…")
        self.bar.setRange(0, 0)
        self.btn_cancel.setEnabled(True)
        self.worker = ScanWorker(options)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.timer.start()
        self.worker.start()

    def cancel(self) -> None:
        if self.worker:
            self.worker.cancel()
            self.btn_cancel.setEnabled(False)
            self.lbl_phase.setText("Cancelando… os resultados parciais serão exibidos.")

    def _tick(self) -> None:
        self.c_time.set(fmt_duration(time.monotonic() - self._t0))

    def _on_progress(self, p: ScanProgress) -> None:
        if not (self.worker and self.worker.cancelled):
            self.lbl_phase.setText(p.phase or "Analisando…")
        if p.percent is None or p.percent < 0:
            if self.bar.maximum() != 0:
                self.bar.setRange(0, 0)
        else:
            if self.bar.maximum() == 0:
                self.bar.setRange(0, 1000)
            self.bar.setValue(int(min(100.0, p.percent) * 10))
        fm = self.lbl_path.fontMetrics()
        self.lbl_path.setText(fm.elidedText(p.current_path or "", Qt.TextElideMode.ElideMiddle,
                                            max(200, self.lbl_path.width() - 10)))
        self.c_files.set(fmt_int(p.files_scanned))
        self.c_bytes.set(fmt_size(p.bytes_scanned))
        self.c_findings.set(fmt_int(p.findings_count))
        self.c_errors.set(fmt_int(p.errors))
        cats = sorted((p.categories or {}).items(), key=lambda kv: -kv[1])
        if self.cats.count() != len(cats):
            self.cats.clear()
            self.cats.addItems(["" for _ in cats])
        for i, (name, n) in enumerate(cats):
            self.cats.item(i).setText(f"{name}  —  {fmt_int(n)} item(ns)")

    def _finish_ui(self, text: str) -> None:
        self.timer.stop()
        self._tick()
        self.btn_cancel.setEnabled(False)
        self.bar.setRange(0, 100)
        self.bar.setValue(100)
        self.lbl_phase.setText(text)

    def _on_finished(self, result) -> None:
        self._finish_ui("Análise cancelada (resultados parciais)." if getattr(result, "cancelled", False)
                        else "Análise concluída.")
        if result is not None:
            self.c_files.set(fmt_int(result.files_scanned))
            self.c_bytes.set(fmt_size(result.bytes_scanned))
            self.c_findings.set(fmt_int(len(result.findings)))
        self.scanFinished.emit(result)

    def _on_error(self, msg: str) -> None:
        self._finish_ui("Falha na análise.")
        self.bar.setValue(0)
        self.scanFailed.emit(msg)
