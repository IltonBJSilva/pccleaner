"""Páginas da janela principal."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget


class Page(QWidget):
    """Base: página com layout vertical e margens padrão."""

    title = ""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("page")
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(24, 20, 24, 20)
        self.root.setSpacing(12)

    def on_show(self) -> None:
        """Chamado quando a página fica visível."""


def scrollable(inner: QWidget) -> QScrollArea:
    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    sa.setWidget(inner)
    return sa
