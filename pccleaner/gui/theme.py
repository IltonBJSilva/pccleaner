"""Temas (QSS) escuro e claro."""
from __future__ import annotations

from PySide6.QtGui import QColor

from pccleaner.core.models import SafetyLevel

SAFETY_COLORS = {
    SafetyLevel.SAFE: "#2ea043",
    SafetyLevel.REVIEW: "#d4a72c",
    SafetyLevel.CAUTION: "#e8772e",
    SafetyLevel.PROTECTED: "#6e7681",
}

PALETTES = {
    "dark": {
        "bg": "#14171c", "surface": "#1c2028", "surface2": "#232833", "border": "#2f3542",
        "text": "#e6e9ef", "muted": "#9aa3b2", "accent": "#3b82f6", "accent2": "#06b6d4",
        "accent_hover": "#5596f8", "danger": "#ef4444", "sel": "#2b4a7a", "sidebar": "#101318",
    },
    "light": {
        "bg": "#f4f6fa", "surface": "#ffffff", "surface2": "#eef1f6", "border": "#d5dbe5",
        "text": "#1d2430", "muted": "#5d6878", "accent": "#2563eb", "accent2": "#0891b2",
        "accent_hover": "#3b76f0", "danger": "#dc2626", "sel": "#cfe0ff", "sidebar": "#e8ecf3",
    },
}

_current = "dark"


def current() -> dict[str, str]:
    return PALETTES[_current]


def color(name: str) -> QColor:
    return QColor(current()[name])


def stylesheet(theme: str = "dark") -> str:
    global _current
    _current = theme if theme in PALETTES else "dark"
    p = PALETTES[_current]
    return f"""
* {{ font-family: "Segoe UI", "Segoe UI Variable", sans-serif; font-size: 10pt; }}
QMainWindow, QDialog, QWidget#page {{ background: {p['bg']}; color: {p['text']}; }}
QWidget {{ color: {p['text']}; }}
QLabel {{ background: transparent; }}
QLabel#h1 {{ font-size: 18pt; font-weight: 600; }}
QLabel#h2 {{ font-size: 12pt; font-weight: 600; }}
QLabel#muted {{ color: {p['muted']}; }}
QLabel#bigValue {{ font-size: 17pt; font-weight: 600; color: {p['text']}; }}
QLabel#hint {{ color: {p['muted']}; font-style: italic; }}
QFrame#card {{ background: {p['surface']}; border: 1px solid {p['border']}; border-radius: 10px; }}
QListWidget#sidebar {{ background: {p['sidebar']}; border: none; padding-top: 8px; outline: 0; }}
QListWidget#sidebar::item {{ padding: 11px 16px; margin: 2px 8px; border-radius: 8px; color: {p['muted']}; }}
QListWidget#sidebar::item:selected {{ background: {p['accent']}; color: white; }}
QListWidget#sidebar::item:hover:!selected {{ background: {p['surface2']}; color: {p['text']}; }}
QLabel#brand {{ font-size: 14pt; font-weight: 700; padding: 16px 18px 6px 18px; color: {p['text']}; background: {p['sidebar']}; }}
QPushButton {{ background: {p['surface2']}; border: 1px solid {p['border']}; border-radius: 7px;
               padding: 6px 14px; color: {p['text']}; }}
QPushButton:hover {{ border-color: {p['accent']}; }}
QPushButton:pressed {{ background: {p['border']}; }}
QPushButton:disabled {{ color: {p['muted']}; background: {p['surface']}; border-color: {p['surface2']}; }}
QPushButton#primary {{ background: {p['accent']}; border: none; color: white; font-weight: 600; }}
QPushButton#primary:hover {{ background: {p['accent_hover']}; }}
QPushButton#primary:disabled {{ background: {p['border']}; color: {p['muted']}; }}
QPushButton#big {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {p['accent']}, stop:1 {p['accent2']});
                   border: none; color: white; font-size: 14pt; font-weight: 700; padding: 14px 40px; border-radius: 10px; }}
QPushButton#big:disabled {{ background: {p['border']}; color: {p['muted']}; }}
QPushButton#danger {{ background: {p['danger']}; border: none; color: white; font-weight: 600; }}
QPushButton#danger:disabled {{ background: {p['border']}; color: {p['muted']}; }}
QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTextEdit {{ background: {p['surface']}; border: 1px solid {p['border']};
               border-radius: 6px; padding: 5px 8px; selection-background-color: {p['accent']}; }}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{ border-color: {p['accent']}; }}
QComboBox QAbstractItemView {{ background: {p['surface']}; selection-background-color: {p['accent']}; }}
QTableView, QTreeView, QListWidget, QTableWidget, QTreeWidget {{ background: {p['surface']}; alternate-background-color: {p['surface2']};
               border: 1px solid {p['border']}; border-radius: 8px; gridline-color: {p['border']};
               selection-background-color: {p['sel']}; selection-color: {p['text']}; }}
QHeaderView::section {{ background: {p['surface2']}; color: {p['muted']}; border: none;
               border-bottom: 1px solid {p['border']}; padding: 6px; font-weight: 600; }}
QProgressBar {{ background: {p['surface2']}; border: none; border-radius: 5px; height: 10px; text-align: center; color: {p['text']}; }}
QProgressBar::chunk {{ border-radius: 5px; background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {p['accent']}, stop:1 {p['accent2']}); }}
QCheckBox {{ spacing: 8px; }}
QScrollArea {{ border: none; background: transparent; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QSplitter::handle {{ background: {p['border']}; }}
QStatusBar {{ background: {p['sidebar']}; color: {p['muted']}; }}
QToolTip {{ background: {p['surface2']}; color: {p['text']}; border: 1px solid {p['border']}; }}
QGroupBox {{ border: 1px solid {p['border']}; border-radius: 8px; margin-top: 14px; padding-top: 8px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; color: {p['muted']}; }}
QTabWidget::pane {{ border: 1px solid {p['border']}; border-radius: 8px; }}
QTabBar::tab {{ background: {p['surface2']}; padding: 7px 16px; border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 2px; }}
QTabBar::tab:selected {{ background: {p['accent']}; color: white; }}
"""
