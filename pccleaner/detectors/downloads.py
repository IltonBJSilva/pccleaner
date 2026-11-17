"""Downloads: instaladores antigos (listados individualmente) e total informativo."""
from __future__ import annotations

from pccleaner.core.models import Category as Cat, Rule

from ._base import NONE, RV, WHOLE, rule

DOWNLOADS_TOTAL_RULE_ID = "downloads.total"
INSTALLER_EXTS = ("exe", "msi", "msix", "msixbundle", "appx", "iso", "zip", "7z", "rar")


def rules() -> list[Rule]:
    d = r"%USERPROFILE%\Downloads"
    return [
        rule("downloads.installers", "Instalador/arquivo antigo em Downloads", Cat.INSTALLERS, "Downloads", RV,
             "Instaladores e pacotes compactados baixados há mais de 30 dias. Normalmente não são mais necessários "
             "depois que o programa foi instalado.",
             "Revise cada arquivo: mantenha os que você não conseguiria baixar de novo.", WHOLE,
             [rf"{d}\*.{e}" for e in INSTALLER_EXTS], min_age_days=30),
        rule(DOWNLOADS_TOTAL_RULE_ID, "Pasta Downloads (total)", Cat.DOWNLOADS, "Downloads", RV,
             "Tamanho total da pasta Downloads, apenas para referência.",
             "Apenas informativo: abra a pasta e decida manualmente o que manter.", NONE, [d]),
    ]
