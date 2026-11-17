"""Infraestrutura de workers em segundo plano (QObject + QThread).

Cada worker roda `work()` numa QThread própria e comunica-se com a GUI apenas por sinais
(entregues via fila na thread principal), de modo que a interface nunca congela.
"""
from __future__ import annotations

import logging
import time
import traceback
from typing import Any, Callable

from PySide6.QtCore import QObject, QThread, Signal, Slot

from pccleaner.core.models import CancelToken

log = logging.getLogger(__name__)

# Mantém referências vivas dos workers em execução (evita coleta de QThread ativa).
_ACTIVE: set["BaseWorker"] = set()


class BaseWorker(QObject):
    progress = Signal(object)
    finished = Signal(object)
    error = Signal(str)

    #: intervalo mínimo entre sinais de progresso (s)
    throttle_interval = 0.1

    def __init__(self) -> None:
        super().__init__()
        self.cancel_token = CancelToken()
        self._thread: QThread | None = None
        self._last_emit = 0.0

    # ------------------------------------------------------------------ API pública
    def start(self) -> "BaseWorker":
        th = QThread()
        self._thread = th
        self.moveToThread(th)
        th.started.connect(self._run)
        th.finished.connect(self._on_thread_finished)
        _ACTIVE.add(self)
        th.start()
        return self

    def cancel(self) -> None:
        self.cancel_token.cancel()

    @property
    def cancelled(self) -> bool:
        return self.cancel_token.cancelled

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.isRunning()

    def wait(self, msecs: int = 5000) -> bool:
        if self._thread is None:
            return True
        return self._thread.wait(msecs)

    # ------------------------------------------------------------------ subclasses
    def work(self) -> Any:  # pragma: no cover - abstrato
        raise NotImplementedError

    def emit_progress(self, payload: Any, force: bool = False) -> None:
        """Emite progresso com limitação de frequência (no máx. ~10/s)."""
        t = time.monotonic()
        if force or t - self._last_emit >= self.throttle_interval:
            self._last_emit = t
            self.progress.emit(payload)

    # ------------------------------------------------------------------ interno
    @Slot()
    def _run(self) -> None:
        try:
            result = self.work()
        except Exception as exc:  # noqa: BLE001
            log.error("Falha em %s: %s\n%s", type(self).__name__, exc, traceback.format_exc())
            self.error.emit(_friendly_error(exc))
        else:
            self.finished.emit(result)
        finally:
            if self._thread is not None:
                self._thread.quit()

    @Slot()
    def _on_thread_finished(self) -> None:
        _ACTIVE.discard(self)


def _friendly_error(exc: BaseException) -> str:
    if isinstance(exc, ImportError):
        return f"Módulo do PCCleaner indisponível: {exc}"
    return f"{type(exc).__name__}: {exc}"


def active_workers() -> list[BaseWorker]:
    return list(_ACTIVE)


def cancel_all(wait_ms: int = 3000) -> None:
    """Cancela e aguarda todos os workers ativos (usado ao fechar o app)."""
    workers = list(_ACTIVE)
    for w in workers:
        w.cancel()
    deadline = time.monotonic() + wait_ms / 1000
    for w in workers:
        remaining = max(0, int((deadline - time.monotonic()) * 1000))
        w.wait(remaining)


class FunctionWorker(BaseWorker):
    """Executa uma função arbitrária fora da thread da GUI."""

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._fn, self._args, self._kwargs = fn, args, kwargs

    def work(self) -> Any:
        return self._fn(*self._args, **self._kwargs)
