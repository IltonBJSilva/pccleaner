"""Ponto de entrada do PCCleaner (usado também pelo PyInstaller)."""
import sys

from pccleaner.gui.app import main

if __name__ == "__main__":
    sys.exit(main())
