"""Widgets reutilizáveis: cartões, gráfico de barras (QPainter) e delegate de segurança."""
from __future__ import annotations

from typing import Callable, Sequence

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QColor, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QProgressBar, QSizePolicy,
                               QStyle, QStyledItemDelegate, QVBoxLayout, QWidget)

from pccleaner.core.models import SafetyLevel
from pccleaner.gui import theme
from pccleaner.gui.utils import fmt_size


def make_label(text: str = "", obj: str | None = None, wrap: bool = False) -> QLabel:
    lb = QLabel(text)
    if obj:
        lb.setObjectName(obj)
    lb.setWordWrap(wrap)
    return lb


class Card(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(16, 14, 16, 14)
        self.lay.setSpacing(6)


class StatCard(Card):
    def __init__(self, title: str, value: str = "—", subtitle: str = "") -> None:
        super().__init__()
        self.title = make_label(title, "muted")
        self.value = make_label(value, "bigValue")
        self.subtitle = make_label(subtitle, "muted", wrap=True)
        for w in (self.title, self.value, self.subtitle):
            self.lay.addWidget(w)
        self.setMinimumWidth(170)

    def set(self, value: str, subtitle: str | None = None) -> None:
        self.value.setText(value)
        if subtitle is not None:
            self.subtitle.setText(subtitle)


class DriveCard(Card):
    def __init__(self, drive: dict) -> None:
        super().__init__()
        letter = str(drive.get("letter", "?")).rstrip(":\\") + ":"
        total = int(drive.get("total") or 0)
        used = int(drive.get("used") or 0)
        free = int(drive.get("free") or max(0, total - used))
        pct = int(round(used * 100 / total)) if total else 0
        head = QHBoxLayout()
        head.addWidget(make_label(f"💽  Unidade {letter}", "h2"))
        head.addStretch(1)
        head.addWidget(make_label(f"{pct}% usado", "muted"))
        self.lay.addLayout(head)
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(pct)
        bar.setTextVisible(False)
        bar.setFixedHeight(10)
        if pct >= 90:
            bar.setStyleSheet("QProgressBar::chunk { background: #ef4444; border-radius: 5px; }")
        self.lay.addWidget(bar)
        self.lay.addWidget(make_label(
            f"Usado {fmt_size(used)}  ·  Livre {fmt_size(free)}  ·  Total {fmt_size(total)}", "muted"))
        self.setMinimumWidth(260)


class HBarChart(QWidget):
    """Gráfico de barras horizontais desenhado com QPainter (sem QtCharts)."""

    ROW_H = 26

    def __init__(self, title: str = "", formatter: Callable[[float], str] = fmt_size,
                 max_rows: int = 15, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.title = title
        self.formatter = formatter
        self.max_rows = max_rows
        self.data: list[tuple[str, float, str]] = []
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMouseTracking(True)
        self._update_height()

    def set_data(self, rows: Sequence[tuple]) -> None:
        """rows: (rótulo, valor[, tooltip])"""
        clean: list[tuple[str, float, str]] = []
        for r in rows:
            label, value = str(r[0]), float(r[1] or 0)
            tip = str(r[2]) if len(r) > 2 else label
            clean.append((label, value, tip))
        clean.sort(key=lambda x: x[1], reverse=True)
        self.data = clean[: self.max_rows]
        self._update_height()
        self.update()

    def _update_height(self) -> None:
        self.setFixedHeight(34 + max(1, len(self.data)) * self.ROW_H + 8)

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(480, self.height())

    def _row_at(self, y: float) -> int:
        idx = int((y - 34) // self.ROW_H)
        return idx if 0 <= idx < len(self.data) else -1

    def mouseMoveEvent(self, ev) -> None:  # noqa: N802
        i = self._row_at(ev.position().y())
        self.setToolTip(f"{self.data[i][2]}\n{self.formatter(self.data[i][1])}" if i >= 0 else "")

    def paintEvent(self, _ev) -> None:  # noqa: N802
        pal = theme.current()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w = self.width()
        f = p.font()
        f.setBold(True)
        f.setPointSizeF(f.pointSizeF() + 1)
        p.setFont(f)
        p.setPen(QColor(pal["text"]))
        p.drawText(QRectF(4, 4, w - 8, 24), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                   self.title)
        f.setBold(False)
        f.setPointSizeF(f.pointSizeF() - 1)
        p.setFont(f)
        fm = QFontMetrics(f)
        if not self.data:
            p.setPen(QColor(pal["muted"]))
            p.drawText(QRectF(4, 34, w - 8, self.ROW_H), Qt.AlignmentFlag.AlignLeft, "Sem dados")
            p.end()
            return
        label_w = min(int(w * 0.38), 280)
        value_w = 90
        bar_x = label_w + 10
        bar_w_max = max(10, w - bar_x - value_w - 10)
        vmax = max(d[1] for d in self.data) or 1
        accent, accent2 = QColor(pal["accent"]), QColor(pal["accent2"])
        n = len(self.data)
        for i, (label, value, _tip) in enumerate(self.data):
            y = 34 + i * self.ROW_H
            p.setPen(QColor(pal["text"]))
            text = fm.elidedText(label, Qt.TextElideMode.ElideMiddle, label_w - 4)
            p.drawText(QRectF(4, y, label_w, self.ROW_H - 4),
                       Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, text)
            bw = max(2.0, bar_w_max * value / vmax)
            t = i / max(1, n - 1)
            c = QColor.fromRgbF(accent.redF() * (1 - t) + accent2.redF() * t,
                                accent.greenF() * (1 - t) + accent2.greenF() * t,
                                accent.blueF() * (1 - t) + accent2.blueF() * t)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(c)
            p.drawRoundedRect(QRectF(bar_x, y + 4, bw, self.ROW_H - 12), 4, 4)
            p.setPen(QColor(pal["muted"]))
            p.drawText(QRectF(bar_x + bw + 6, y, value_w + 40, self.ROW_H - 4),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, self.formatter(value))
        p.end()


class SafetyBadgeDelegate(QStyledItemDelegate):
    """Desenha o nível de segurança como um selo colorido."""

    def paint(self, painter: QPainter, option, index) -> None:
        value = index.data(Qt.ItemDataRole.UserRole + 10)
        if not isinstance(value, SafetyLevel):
            super().paint(painter, option, index)
            return
        painter.save()
        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(option.rect, theme.color("sel"))
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        text = value.label
        fm = QFontMetrics(option.font)
        r = option.rect.adjusted(6, 5, 0, -5)
        r.setWidth(min(fm.horizontalAdvance(text) + 18, max(10, option.rect.width() - 12)))
        col = QColor(theme.SAFETY_COLORS[value])
        painter.setPen(QPen(col, 1))
        fill = QColor(col)
        fill.setAlpha(55)
        painter.setBrush(fill)
        painter.drawRoundedRect(r, r.height() / 2, r.height() / 2)
        painter.setPen(col.lighter(130) if theme._current == "dark" else col.darker(130))
        painter.drawText(r, Qt.AlignmentFlag.AlignCenter, text)
        painter.restore()

    def sizeHint(self, option, index) -> QSize:  # noqa: N802
        s = super().sizeHint(option, index)
        return QSize(max(s.width(), 96), max(s.height(), 26))
