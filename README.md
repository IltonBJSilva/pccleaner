# PCCleaner

Limpador de disco para Windows (PySide6) focado em segurança: analisa caches, temporários, logs,
dependências de projeto, instaladores, duplicados e arquivos grandes/antigos, explica por que cada
item foi encontrado e só limpa o que você marcar — com quarentena restaurável.

Páginas: Painel, Análise (tempo real, cancelável), Resultados (filtros, níveis de segurança,
detalhes, comando oficial copiável), Armazenamento (gráficos), Duplicados (sempre mantém uma cópia),
Quarentena, Histórico (exporta HTML/JSON/CSV) e Configurações. O app não pede elevação ao iniciar;
use “Reabrir como administrador” no Painel para itens 🛡.

## Desenvolvimento

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install PySide6-Essentials pyinstaller pytest pillow
.venv\Scripts\python.exe main.py        # ou: -m pccleaner
$env:QT_QPA_PLATFORM = "offscreen"; .venv\Scripts\python.exe -m pytest -q
```

## Build

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1 [-SkipTests]
```

Gera `dist\PCCleaner\PCCleaner.exe` (onedir, sem console). Ícone gerado por `assets\make_icon.py`.
Dados, configurações e logs ficam em `%LOCALAPPDATA%\PCCleaner`.
