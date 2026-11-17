"""Modelo de dados (QAbstractTableModel) + proxy de filtro/ordenação para os achados.

Projetado para dezenas de milhares de linhas: textos de exibição são pré-calculados por linha
e as contagens de seleção são mantidas incrementalmente.
"""
from __future__ import annotations

import os
from typing import Any, Iterable

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt, Signal
from PySide6.QtGui import QColor

from pccleaner.core.models import Finding, SafetyLevel
from pccleaner.gui import theme
from pccleaner.gui.utils import fmt_dt, fmt_int, fmt_size

SORT_ROLE = Qt.ItemDataRole.UserRole + 1
FINDING_ROLE = Qt.ItemDataRole.UserRole + 2
SAFETY_ROLE = Qt.ItemDataRole.UserRole + 10

COLUMNS = ["✓", "Categoria", "Nome", "Local", "Tamanho", "Arquivos", "Última modificação",
           "App", "Segurança", "Ação recomendada"]
COL_CHECK, COL_CAT, COL_NAME, COL_PATH, COL_SIZE, COL_FILES, COL_MTIME, COL_APP, COL_SAFETY, COL_ACTION = range(10)


def _is_checked(value: Any) -> bool:
    try:
        return Qt.CheckState(value) == Qt.CheckState.Checked
    except (ValueError, TypeError):
        return value == Qt.CheckState.Checked or value == 2


class FindingsModel(QAbstractTableModel):
    selectionChanged = Signal(object, object)  # (quantidade, bytes) — object: bytes > 2^31

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[Finding] = []
        self._display: list[tuple] = []
        self._sel_count = 0
        self._sel_bytes = 0

    # ------------------------------------------------------------------ dados
    def set_findings(self, findings: Iterable[Finding]) -> None:
        self.beginResetModel()
        self._rows = list(findings)
        self._display = [self._make_display(f) for f in self._rows]
        self.endResetModel()
        self._recount()

    @staticmethod
    def _make_display(f: Finding) -> tuple:
        name = f.name or os.path.basename(f.path.rstrip("\\/")) or f.path
        admin = "🛡 " if f.requires_admin else ""
        return (admin + f.category.value, name, f.path, fmt_size(f.size_bytes), fmt_int(f.file_count),
                fmt_dt(f.last_modified), f.app or "—", f.safety.label, f.recommendation)

    def findings(self) -> list[Finding]:
        return self._rows

    def finding_at(self, row: int) -> Finding | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def refresh_rows(self) -> None:
        """Recalcula textos (após limpeza alterar tamanhos/contagens)."""
        self._display = [self._make_display(f) for f in self._rows]
        if self._rows:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self._rows) - 1, len(COLUMNS) - 1))
        self._recount()

    # ------------------------------------------------------------------ seleção
    def _recount(self) -> None:
        sel = [f for f in self._rows if f.selected]
        self._sel_count = len(sel)
        self._sel_bytes = sum(f.size_bytes for f in sel)
        self.selectionChanged.emit(self._sel_count, self._sel_bytes)

    def selected_findings(self) -> list[Finding]:
        return [f for f in self._rows if f.selected and f.cleanable]

    def selection_stats(self) -> tuple[int, int]:
        return self._sel_count, self._sel_bytes

    def set_checked_rows(self, rows: Iterable[int], checked: bool) -> None:
        changed = False
        for r in rows:
            f = self._rows[r]
            if f.cleanable and f.selected != checked:
                f.selected = checked
                changed = True
        if changed and self._rows:
            self.dataChanged.emit(self.index(0, COL_CHECK), self.index(len(self._rows) - 1, COL_CHECK),
                                  [Qt.ItemDataRole.CheckStateRole])
        self._recount()

    def clear_selection(self) -> None:
        self.set_checked_rows(range(len(self._rows)), False)

    # ------------------------------------------------------------------ Qt API
    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section]
        return None

    def flags(self, index):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        fl = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == COL_CHECK and self._rows[index.row()].cleanable:
            fl |= Qt.ItemFlag.ItemIsUserCheckable
        return fl

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        r, c = index.row(), index.column()
        f = self._rows[r]
        if role == Qt.ItemDataRole.DisplayRole:
            if c == COL_CHECK:
                return None if f.cleanable else "🔒"
            return self._display[r][c - 1]
        if role == SORT_ROLE:
            if c == COL_CHECK:
                return 1 if f.selected else 0
            if c == COL_SIZE:
                return f.size_bytes
            if c == COL_FILES:
                return f.file_count
            if c == COL_MTIME:
                return f.last_modified or 0.0
            if c == COL_SAFETY:
                return f.safety.rank
            return self._display[r][c - 1].lower()
        if role == Qt.ItemDataRole.CheckStateRole and c == COL_CHECK and f.cleanable:
            return Qt.CheckState.Checked if f.selected else Qt.CheckState.Unchecked
        if role == SAFETY_ROLE and c == COL_SAFETY:
            return f.safety
        if role == FINDING_ROLE:
            return f
        if role == Qt.ItemDataRole.TextAlignmentRole and c in (COL_SIZE, COL_FILES):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.ForegroundRole and f.safety is SafetyLevel.PROTECTED:
            return QColor(theme.current()["muted"])
        if role == Qt.ItemDataRole.ToolTipRole:
            if c == COL_CHECK and not f.cleanable:
                return "Item protegido ou apenas informativo — não pode ser limpo pelo app."
            if c == COL_CAT and f.requires_admin:
                return "🛡 Exige executar como administrador"
            if c in (COL_PATH, COL_NAME):
                return f.path
            if c == COL_ACTION:
                return f.recommendation
        return None

    def setData(self, index, value, role=Qt.ItemDataRole.EditRole) -> bool:  # noqa: N802
        if not index.isValid() or role != Qt.ItemDataRole.CheckStateRole or index.column() != COL_CHECK:
            return False
        f = self._rows[index.row()]
        if not f.cleanable:
            return False
        new = _is_checked(value)
        if new == f.selected:
            return True
        f.selected = new
        self._sel_count += 1 if new else -1
        self._sel_bytes += f.size_bytes if new else -f.size_bytes
        self.dataChanged.emit(index, index, [Qt.ItemDataRole.CheckStateRole])
        self.selectionChanged.emit(self._sel_count, self._sel_bytes)
        return True


class FindingsProxy(QSortFilterProxyModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._category: str | None = None
        self._safety: SafetyLevel | None = None
        self._text = ""
        self.setSortRole(SORT_ROLE)
        self.setDynamicSortFilter(False)

    def _refilter(self, setter) -> None:
        """Aplica a mudança de filtro com a API nova (Qt >= 6.10) ou a clássica."""
        if hasattr(self, "beginFilterChange"):
            self.beginFilterChange()
            setter()
            self.endFilterChange(QSortFilterProxyModel.Direction.Rows)
        else:  # pragma: no cover - Qt antigo
            setter()
            self.invalidateFilter()

    def set_category(self, cat: str | None) -> None:
        self._refilter(lambda: setattr(self, "_category", cat or None))

    def set_safety(self, safety: SafetyLevel | None) -> None:
        self._refilter(lambda: setattr(self, "_safety", safety))

    def set_text(self, text: str) -> None:
        self._refilter(lambda: setattr(self, "_text", (text or "").strip().lower()))

    def filterAcceptsRow(self, source_row, source_parent) -> bool:  # noqa: N802
        f = self.sourceModel().finding_at(source_row)
        if f is None:
            return False
        if self._category and f.category.value != self._category:
            return False
        if self._safety is not None and f.safety is not self._safety:
            return False
        t = self._text
        if t and t not in f.path.lower() and t not in (f.name or "").lower() and t not in (f.app or "").lower():
            return False
        return True

    def visible_source_rows(self) -> list[int]:
        return [self.mapToSource(self.index(r, 0)).row() for r in range(self.rowCount())]
