"""Configurações persistentes."""
from __future__ import annotations

from PySide6.QtWidgets import (QCheckBox, QComboBox, QFormLayout, QHBoxLayout, QMessageBox,
                               QPushButton, QSpinBox, QWidget)

from pccleaner.config import APP_VERSION, data_dir
from pccleaner.gui.pages import Page
from pccleaner.gui.state import AppState
from pccleaner.gui.widgets import Card, make_label


def _spin(lo: int, hi: int, suffix: str) -> QSpinBox:
    s = QSpinBox()
    s.setRange(lo, hi)
    s.setSuffix(suffix)
    s.setMinimumWidth(140)
    return s


class SettingsPage(Page):
    title = "Configurações"

    def __init__(self, state: AppState, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state
        self.root.addWidget(make_label("Configurações", "h1"))
        card = Card()
        form = QFormLayout()
        form.setSpacing(12)
        self.sp_large = _spin(10, 1_000_000, " MB")
        self.sp_old = _spin(1, 36500, " dias")
        self.chk_q = QCheckBox("Usar quarentena por padrão (permite restaurar itens limpos)")
        self.sp_qmax = _spin(1, 1_000_000, " MB")
        self.sp_keep = _spin(1, 3650, " dias")
        self.cmb_theme = QComboBox()
        self.cmb_theme.addItem("Escuro", "dark")
        self.cmb_theme.addItem("Claro", "light")
        form.addRow("Arquivos grandes a partir de:", self.sp_large)
        form.addRow("Arquivos antigos (sem modificação há):", self.sp_old)
        form.addRow("", self.chk_q)
        form.addRow("Tamanho máximo por item na quarentena:", self.sp_qmax)
        form.addRow("Manter lotes da quarentena por:", self.sp_keep)
        form.addRow("Tema:", self.cmb_theme)
        card.lay.addLayout(form)
        row = QHBoxLayout()
        row.addStretch(1)
        btn_reset = QPushButton("Descartar alterações")
        btn_reset.clicked.connect(self.load)
        btn_save = QPushButton("Salvar")
        btn_save.setObjectName("primary")
        btn_save.clicked.connect(self.save)
        row.addWidget(btn_reset)
        row.addWidget(btn_save)
        card.lay.addLayout(row)
        self.root.addWidget(card)
        self.root.addWidget(make_label(f"PCCleaner {APP_VERSION} · Dados e logs em: {data_dir()}", "muted"))
        self.root.addStretch(1)
        self.load()

    def load(self) -> None:
        s = self.state.settings
        self.sp_large.setValue(int(s.large_file_threshold_mb))
        self.sp_old.setValue(int(s.old_file_days))
        self.chk_q.setChecked(bool(s.use_quarantine))
        self.sp_qmax.setValue(int(s.quarantine_max_mb))
        self.sp_keep.setValue(int(s.quarantine_keep_days))
        self.cmb_theme.setCurrentIndex(max(0, self.cmb_theme.findData(s.theme)))

    def apply_to_settings(self) -> None:
        s = self.state.settings
        s.large_file_threshold_mb = self.sp_large.value()
        s.old_file_days = self.sp_old.value()
        s.use_quarantine = self.chk_q.isChecked()
        s.quarantine_max_mb = self.sp_qmax.value()
        s.quarantine_keep_days = self.sp_keep.value()
        s.theme = self.cmb_theme.currentData()

    def save(self) -> None:
        self.apply_to_settings()
        try:
            self.state.save_settings()
        except OSError as exc:
            QMessageBox.critical(self, "Configurações", f"Falha ao salvar: {exc}")
            return
        QMessageBox.information(self, "Configurações", "Configurações salvas.")
