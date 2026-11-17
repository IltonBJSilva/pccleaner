"""Diálogos do fluxo de limpeza: confirmação → progresso → relatório."""
from __future__ import annotations

import logging
import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QDialog, QDialogButtonBox,
                               QHBoxLayout, QHeaderView, QLabel, QListWidget, QMessageBox,
                               QProgressBar, QPushButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from pccleaner.config import Settings
from pccleaner.core.models import CleanReport, Finding, SafetyLevel
from pccleaner.gui.utils import fmt_size, is_admin, refusal_reason
from pccleaner.gui.widgets import make_label
from pccleaner.workers import CleanWorker

log = logging.getLogger(__name__)

MAX_LISTED = 2000  # linhas mostradas na tabela de confirmação


def _consequences(findings: list[Finding], settings: Settings | None = None) -> list[str]:
    try:
        from pccleaner.cleaner import preview_consequences
        if settings is not None:
            try:
                return list(preview_consequences(
                    findings, use_quarantine=settings.use_quarantine,
                    quarantine_max_bytes=int(settings.quarantine_max_mb) * 1024 * 1024))
            except TypeError:
                pass
        return list(preview_consequences(findings))
    except Exception as exc:  # noqa: BLE001
        log.info("preview_consequences indisponível: %s", exc)
        out = []
        if any(f.category.value.startswith("Cache") for f in findings):
            out.append("Aplicativos e navegadores podem ficar mais lentos na primeira abertura "
                       "enquanto recriam o cache.")
        if any(f.safety in (SafetyLevel.REVIEW, SafetyLevel.CAUTION) for f in findings):
            out.append("Alguns itens exigem revisão: confira se não há arquivos que você ainda usa.")
        return out


def split_cleanable(findings: list[Finding]) -> tuple[list[Finding], list[tuple[Finding, str]]]:
    """Separa os itens selecionados em (limpáveis, recusados com motivo).

    Itens não selecionados são ignorados. Recusados: protegidos/informativos ou caminhos que o
    backend recusará (raiz de unidade, área protegida, raiz de projeto, pasta do app...).
    """
    ok: list[Finding] = []
    refused: list[tuple[Finding, str]] = []
    for f in findings:
        if not f.selected:
            continue
        if not f.cleanable:
            refused.append((f, "Item protegido ou apenas informativo"))
            continue
        reason = refusal_reason(f.path)
        if reason:
            refused.append((f, reason))
        else:
            ok.append(f)
    return ok, refused


class CleanConfirmDialog(QDialog):
    def __init__(self, findings: list[Finding], settings: Settings, parent: QWidget | None = None,
                 title: str = "Confirmar limpeza", force_quarantine: bool = False) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(940, 660)
        self.findings, self.refused = split_cleanable(findings)
        total = sum(f.size_bytes for f in self.findings)
        lay = QVBoxLayout(self)
        lay.addWidget(make_label(title, "h1"))
        summary = f"<b>{len(self.findings)}</b> itens serão limpos · até <b>{fmt_size(total)}</b> a liberar"
        if self.refused:
            summary += f" · <b>{len(self.refused)}</b> não limpáveis (serão ignorados)"
        lay.addWidget(make_label(summary))

        rows: list[tuple[Finding, str | None]] = [(f, None) for f in self.findings] + list(self.refused)
        table = QTableWidget(min(len(rows), MAX_LISTED), 6)
        table.setHorizontalHeaderLabels(["Nome", "Local", "Tamanho", "Segurança", "Admin", "Status"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        muted = QColor("#9aa3b2")
        for r, (f, reason) in enumerate(rows[:MAX_LISTED]):
            status = f"🚫 Não limpável: {reason}" if reason else "Será limpo"
            vals = [f.name, f.path, fmt_size(f.size_bytes), f.safety.label,
                    "🛡 Sim" if f.requires_admin else "", status]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                it.setToolTip(reason or f.path)
                if reason:
                    it.setForeground(muted)
                table.setItem(r, c, it)
        hh = table.horizontalHeader()
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for c in (0, 2, 3, 4, 5):
            hh.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        self.table = table
        lay.addWidget(table, 1)
        if len(rows) > MAX_LISTED:
            lay.addWidget(make_label(f"… e mais {len(rows) - MAX_LISTED} itens.", "muted"))

        warnings: list[str] = []
        n_review = sum(1 for f in self.findings if f.safety is SafetyLevel.REVIEW)
        n_caution = sum(1 for f in self.findings if f.safety is SafetyLevel.CAUTION)
        n_admin = sum(1 for f in self.findings if f.requires_admin)
        if self.refused:
            warnings.append(f"🚫 {len(self.refused)} item(ns) não podem ser limpos (protegidos, raiz de "
                            f"projeto/unidade ou área do sistema) e não serão enviados à limpeza.")
        if n_caution:
            warnings.append(f"⚠ {n_caution} item(ns) com nível <b>Atenção</b> (dependências, projetos ou "
                            f"arquivos grandes). Verifique antes de continuar.")
        if n_review:
            warnings.append(f"⚠ {n_review} item(ns) marcados para <b>Revisar</b>.")
        if n_admin and not is_admin():
            warnings.append(f"🛡 {n_admin} item(ns) exigem administrador; sem elevação, partes deles "
                            f"serão ignoradas.")
        cons = _consequences(self.findings, settings) if self.findings else []
        text = "".join(f"<p>{w}</p>" for w in warnings)
        if cons:
            text += "<p><b>Consequências esperadas:</b></p><ul>" + "".join(f"<li>{c}</li>" for c in cons) + "</ul>"
        if text:
            info = QLabel(text)
            info.setWordWrap(True)
            info.setTextFormat(Qt.TextFormat.RichText)
            lay.addWidget(info)

        self.chk_quarantine = QCheckBox(
            f"Mover para a quarentena (restaurável por {settings.quarantine_keep_days} dias; "
            f"itens acima de {settings.quarantine_max_mb} MB são apagados direto)")
        self.chk_quarantine.setChecked(settings.use_quarantine or force_quarantine)
        self.chk_quarantine.setEnabled(not force_quarantine)
        lay.addWidget(self.chk_quarantine)
        self.chk_confirm = QCheckBox("Entendo e quero limpar")
        self.chk_confirm.setEnabled(bool(self.findings))
        lay.addWidget(self.chk_confirm)

        btns = QDialogButtonBox()
        self.btn_ok = QPushButton("Limpar agora")
        self.btn_ok.setObjectName("danger")
        self.btn_ok.setEnabled(False)
        btns.addButton(self.btn_ok, QDialogButtonBox.ButtonRole.AcceptRole)
        btns.addButton("Cancelar", QDialogButtonBox.ButtonRole.RejectRole)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        self.chk_confirm.toggled.connect(lambda on: self.btn_ok.setEnabled(on and bool(self.findings)))
        lay.addWidget(btns)

    @property
    def use_quarantine(self) -> bool:
        return self.chk_quarantine.isChecked()


class CleanProgressDialog(QDialog):
    def __init__(self, findings: list[Finding], *, use_quarantine: bool, quarantine_max_bytes: int,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Limpando…")
        self.setModal(True)
        self.resize(560, 170)
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, False)
        self.report: CleanReport | None = None
        self.error: str | None = None
        lay = QVBoxLayout(self)
        lay.addWidget(make_label("Limpando itens selecionados…", "h2"))
        self.lbl = make_label("Preparando…", "muted")
        self.lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(self.lbl)
        self.bar = QProgressBar()
        self.bar.setRange(0, 0)
        lay.addWidget(self.bar)
        row = QHBoxLayout()
        row.addStretch(1)
        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.clicked.connect(self._cancel)
        row.addWidget(self.btn_cancel)
        lay.addLayout(row)
        self.worker = CleanWorker(findings, use_quarantine=use_quarantine,
                                  quarantine_max_bytes=quarantine_max_bytes)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)

    def showEvent(self, ev) -> None:  # noqa: N802
        super().showEvent(ev)
        if not self.worker.is_running() and self.report is None and self.error is None:
            self.worker.start()

    def _cancel(self) -> None:
        self.worker.cancel()
        self.btn_cancel.setEnabled(False)
        self.lbl.setText("Cancelando… aguardando o item atual terminar.")

    def _on_progress(self, payload) -> None:
        current, done, total = payload
        if total > 0:
            self.bar.setRange(0, total)
            self.bar.setValue(done)
        fm = self.lbl.fontMetrics()
        self.lbl.setText(fm.elidedText(f"{done}/{total} · {current}", Qt.TextElideMode.ElideMiddle, 520))

    def _on_finished(self, report) -> None:
        self.report = report
        self.accept()

    def _on_error(self, msg: str) -> None:
        self.error = msg
        self.reject()

    def reject(self) -> None:
        if self.worker.is_running() and self.report is None and self.error is None:
            self._cancel()  # ESC = cancelar, mas espera o worker terminar
            return
        super().reject()


class CleanReportDialog(QDialog):
    def __init__(self, report: CleanReport, parent: QWidget | None = None,
                 refused: list[tuple[Finding, str]] | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Relatório da limpeza")
        self.resize(760, 520)
        lay = QVBoxLayout(self)
        lay.addWidget(make_label("Limpeza cancelada" if report.cancelled else "Limpeza concluída", "h1"))
        skipped = sum(i.files_skipped for i in report.items)
        quarantined = sum(1 for i in report.items if i.quarantined)
        dur = max(0.0, report.finished_at - report.started_at)
        lay.addWidget(make_label(
            f"Espaço liberado: <b>{fmt_size(report.freed_bytes)}</b> · Arquivos removidos: "
            f"<b>{report.files_removed}</b> · Ignorados: <b>{skipped}</b> · Em quarentena: "
            f"<b>{quarantined}</b> itens · Erros: <b>{report.error_count}</b> · Duração: {dur:.1f}s"))
        errors = [f"{i.path}: {e}" for i in report.items for e in i.errors]
        errors += [f"{f.path}: não limpável — {r}" for f, r in (refused or [])]
        if errors:
            lay.addWidget(make_label("Erros / itens ignorados (em uso, sem permissão ou protegidos):", "muted"))
            lst = QListWidget()
            lst.addItems(errors[:5000])
            lay.addWidget(lst, 1)
        else:
            lay.addStretch(1)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        btns.accepted.connect(self.accept)
        lay.addWidget(btns)


def save_clean_history(report: CleanReport, scan_id: str | None) -> None:
    try:
        from pccleaner.database import HistoryDB
        HistoryDB().save_clean(report, scan_id=scan_id)
    except Exception as exc:  # noqa: BLE001
        log.warning("Falha ao salvar limpeza no histórico: %s", exc)


def run_clean_flow(parent: QWidget, findings: list[Finding], settings: Settings, *,
                   scan_id: str | None = None, title: str = "Confirmar limpeza",
                   force_quarantine: bool = False) -> CleanReport | None:
    """Fluxo completo: confirmação, execução com progresso, relatório e histórico."""
    if not any(f.selected and f.cleanable for f in findings):
        QMessageBox.information(parent, "PCCleaner", "Nenhum item limpável selecionado.")
        return None
    dlg = CleanConfirmDialog(findings, settings, parent, title=title, force_quarantine=force_quarantine)
    if dlg.exec() != QDialog.DialogCode.Accepted or not dlg.findings:
        return None
    prog = CleanProgressDialog(dlg.findings, use_quarantine=dlg.use_quarantine,
                               quarantine_max_bytes=int(settings.quarantine_max_mb) * 1024 * 1024,
                               parent=parent)
    prog.exec()
    if prog.report is None:
        QMessageBox.critical(parent, "Erro na limpeza", prog.error or "A limpeza não retornou relatório.")
        return None
    report = prog.report
    if not report.finished_at:
        report.finished_at = time.time()
    save_clean_history(report, scan_id)
    CleanReportDialog(report, parent, dlg.refused).exec()
    return report
