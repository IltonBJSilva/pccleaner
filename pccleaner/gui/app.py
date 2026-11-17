"""Ponto de entrada da GUI."""
from __future__ import annotations

import ctypes
import logging
import sys
import threading
import traceback

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

from pccleaner.config import APP_NAME, APP_VERSION, Settings, logs_dir, setup_logging
from pccleaner.gui import theme
from pccleaner.gui.utils import resource_path

log = logging.getLogger("pccleaner")

_in_hook = False


def _excepthook(exc_type, exc, tb) -> None:
    global _in_hook
    text = "".join(traceback.format_exception(exc_type, exc, tb))
    log.critical("Exceção não tratada:\n%s", text)
    if issubclass(exc_type, KeyboardInterrupt) or _in_hook:
        return
    if QApplication.instance() is None:
        sys.__excepthook__(exc_type, exc, tb)
        return
    _in_hook = True
    try:
        box = QMessageBox(QMessageBox.Icon.Critical, APP_NAME,
                          f"Ocorreu um erro inesperado:\n\n{exc_type.__name__}: {exc}\n\n"
                          f"Detalhes foram gravados no log em:\n{logs_dir()}")
        box.setDetailedText(text)
        box.exec()
    finally:
        _in_hook = False


def _thread_excepthook(args) -> None:
    log.critical("Exceção em thread %s:\n%s", getattr(args.thread, "name", "?"),
                 "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)))


def app_icon() -> QIcon:
    p = resource_path("assets/icon.ico")
    return QIcon(str(p)) if p.exists() else QIcon()


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    log.info("Iniciando %s %s", APP_NAME, APP_VERSION)
    sys.excepthook = _excepthook
    threading.excepthook = _thread_excepthook
    try:  # ícone próprio na barra de tarefas
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(f"PCCleaner.App.{APP_VERSION}")  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication.instance() or QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(APP_NAME)
    app.setWindowIcon(app_icon())
    app.setStyle("Fusion")
    settings = Settings.load()
    app.setStyleSheet(theme.stylesheet(settings.theme))

    from pccleaner.gui.main_window import MainWindow
    win = MainWindow(settings)
    win.show()
    rc = app.exec()
    log.info("Encerrando (código %s)", rc)
    return rc


if __name__ == "__main__":
    sys.exit(main())
