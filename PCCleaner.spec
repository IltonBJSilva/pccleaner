# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec do PCCleaner — modo onedir (inicialização rápida), janela sem console.
# Uso: pyinstaller PCCleaner.spec --noconfirm --clean   (ou ./build.ps1)
import os

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(SPECPATH)

# Qt/Python que o app não usa — reduz bastante o tamanho do pacote.
EXCLUDES = [
    "tkinter", "_tkinter", "pydoc", "pytest", "_pytest", "PIL", "setuptools", "pip",
    "PySide6.QtNetwork", "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuickWidgets",
    "PySide6.QtQuickControls2", "PySide6.QtQuick3D", "PySide6.Qt3DCore", "PySide6.Qt3DRender",
    "PySide6.Qt3DInput", "PySide6.Qt3DLogic", "PySide6.Qt3DExtras", "PySide6.Qt3DAnimation",
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick",
    "PySide6.QtWebChannel", "PySide6.QtWebSockets", "PySide6.QtWebView",
    "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets", "PySide6.QtSpatialAudio",
    "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtGraphs",
    "PySide6.QtPdf", "PySide6.QtPdfWidgets", "PySide6.QtSql", "PySide6.QtTest",
    "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets", "PySide6.QtSvgWidgets",
    "PySide6.QtDesigner", "PySide6.QtHelp", "PySide6.QtUiTools", "PySide6.QtXml",
    "PySide6.QtBluetooth", "PySide6.QtNfc", "PySide6.QtPositioning", "PySide6.QtLocation",
    "PySide6.QtSensors", "PySide6.QtSerialPort", "PySide6.QtSerialBus", "PySide6.QtRemoteObjects",
    "PySide6.QtScxml", "PySide6.QtStateMachine", "PySide6.QtTextToSpeech", "PySide6.QtHttpServer",
    "PySide6.QtConcurrent", "PySide6.QtDBus", "PySide6.QtPrintSupport", "PySide6.QtAxContainer",
]

# DLLs/plugins Qt grandes e desnecessários (substring do caminho de destino).
DROP_PATTERNS = (
    "opengl32sw.dll", "Qt6Quick", "Qt6Qml", "Qt6Pdf", "Qt6Network", "Qt6VirtualKeyboard",
    "Qt6Multimedia", "Qt6WebEngine", "Qt63D", "Qt6Charts", "Qt6Designer", "Qt6OpenGL",
    "qtwebengine", "QtQuick", "QtQml", "avcodec", "avformat", "avutil", "swresample", "swscale",
    "imageformats\\qpdf", "imageformats\\qtiff", "imageformats\\qwebp", "imageformats\\qicns",
    "imageformats\\qtga", "imageformats\\qwbmp", "platforms\\qdirect2d", "platforms\\qminimal",
    "platforms\\qoffscreen", "platformthemes", "networkinformation", "plugins\\tls",
    "generic\\qtuiotouchplugin", "qmltooling", "plugins\\position", "sqldrivers", "plugins\\multimedia",
)


def _keep(entry) -> bool:
    dest = entry[0].replace("/", "\\").lower()
    if any(p.lower() in dest for p in DROP_PATTERNS):
        return False
    # Traduções Qt: mantém só pt_BR.
    if "translations" in dest and dest.endswith(".qm") and "pt_br" not in dest:
        return False
    return True


a = Analysis(
    [os.path.join(ROOT, "main.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[
        (os.path.join(ROOT, "assets", "icon.ico"), "assets"),
        (os.path.join(ROOT, "assets", "icon.png"), "assets"),
    ],
    hiddenimports=collect_submodules("pccleaner"),
    hookspath=[],
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=1,
)
a.binaries = [b for b in a.binaries if _keep(b)]
a.datas = [d for d in a.datas if _keep(d)]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PCCleaner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=os.path.join(ROOT, "assets", "icon.ico"),
    uac_admin=False,
)

coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, upx_exclude=[], name="PCCleaner")
