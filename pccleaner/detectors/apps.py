"""Caches de aplicativos (Electron, jogos, GPU, mídia)."""
from __future__ import annotations

from pccleaner.core.models import Category as Cat, Rule

from ._base import CONTENTS, REC_CLOSE_APP, RV, S, rule

ELECTRON_CACHE_SUBDIRS = ["Cache", "Code Cache", "GPUCache", r"Service Worker\CacheStorage", "DawnCache",
                          "DawnGraphiteCache", "DawnWebGPUCache"]

# (id, nome, raízes de dados Electron)
ELECTRON_APPS: list[tuple[str, str, list[str]]] = [
    ("discord", "Discord", [r"%APPDATA%\discord", r"%APPDATA%\discordptb", r"%APPDATA%\discordcanary"]),
    ("slack", "Slack", [r"%APPDATA%\Slack",
                        r"%LOCALAPPDATA%\Packages\91750D7E.Slack_*\LocalCache\Roaming\Slack"]),
    ("teams_classic", "Microsoft Teams (clássico)", [r"%APPDATA%\Microsoft\Teams"]),
    ("teams_new", "Microsoft Teams", [r"%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\*"]),
    ("vscode", "Visual Studio Code", [r"%APPDATA%\Code"]),
    ("vscode_insiders", "VS Code Insiders", [r"%APPDATA%\Code - Insiders"]),
    ("cursor", "Cursor", [r"%APPDATA%\Cursor"]),
    ("windsurf", "Windsurf", [r"%APPDATA%\Windsurf"]),
    ("antigravity", "Antigravity", [r"%APPDATA%\Antigravity"]),
    ("notion", "Notion", [r"%APPDATA%\Notion"]),
    ("obsidian", "Obsidian", [r"%APPDATA%\obsidian"]),
    ("postman", "Postman", [r"%APPDATA%\Postman"]),
    ("whatsapp", "WhatsApp", [r"%LOCALAPPDATA%\Packages\5319275A.WhatsAppDesktop_*\LocalCache\EBWebView\*"]),
    ("figma", "Figma", [r"%APPDATA%\Figma\Desktop"]),
    ("gitkraken", "GitKraken", [r"%APPDATA%\.gitkraken"]),
    ("claude", "Claude", [r"%APPDATA%\Claude"]),
    ("capcut_cef", "CapCut", [r"%LOCALAPPDATA%\CapCut\User Data\CEF"]),
]


def rules() -> list[Rule]:
    out: list[Rule] = []
    for aid, name, roots in ELECTRON_APPS:
        paths = [rf"{r}\{sub}" for r in roots for sub in ELECTRON_CACHE_SUBDIRS]
        out.append(rule(f"app.{aid}.cache", f"{name} — Cache", Cat.APP_CACHE, name, S,
                        f"Caches web (HTTP, código, GPU) do {name}. Conversas, contas e configurações não são tocadas.",
                        REC_CLOSE_APP, CONTENTS, paths))
    out += [
        rule("app.teams_classic.tmp", "Microsoft Teams (clássico) — temporários", Cat.APP_CACHE,
             "Microsoft Teams (clássico)", S, "Temporários e cache de aplicação do Teams clássico.", REC_CLOSE_APP,
             CONTENTS, [r"%APPDATA%\Microsoft\Teams\tmp", r"%APPDATA%\Microsoft\Teams\Application Cache"]),
        rule("app.vscode.extra", "VS Code — dados em cache e logs", Cat.APP_CACHE, "Visual Studio Code", S,
             "CachedData (código compilado de versões), pacotes VSIX baixados e logs do VS Code/Cursor.",
             REC_CLOSE_APP, CONTENTS,
             [rf"%APPDATA%\{a}\{s}" for a in ("Code", "Code - Insiders", "Cursor", "Windsurf", "Antigravity")
              for s in ("CachedData", "CachedExtensionVSIXs", "CachedProfilesData", "logs")]),
        rule("app.slack.logs", "Slack — logs", Cat.SYSTEM_LOGS, "Slack", S, "Logs do Slack.", REC_CLOSE_APP,
             CONTENTS, [r"%APPDATA%\Slack\logs"]),
        rule("app.spotify.data", "Spotify — cache", Cat.APP_CACHE, "Spotify", S,
             "Cache de dados do Spotify (capas, metadados).", REC_CLOSE_APP, CONTENTS,
             [r"%LOCALAPPDATA%\Spotify\Data",
              r"%LOCALAPPDATA%\Packages\SpotifyAB.SpotifyMusic_*\LocalCache\Spotify\Data"]),
        rule("app.spotify.storage", "Spotify — armazenamento de músicas", Cat.APP_CACHE, "Spotify", RV,
             "Cache de streaming do Spotify. Pode conter músicas baixadas para ouvir offline.",
             "Revise: músicas baixadas para uso offline terão de ser baixadas novamente.", CONTENTS,
             [r"%LOCALAPPDATA%\Spotify\Storage",
              r"%LOCALAPPDATA%\Packages\SpotifyAB.SpotifyMusic_*\LocalCache\Spotify\Storage"]),
        # Steam
        rule("app.steam.htmlcache", "Steam — cache do navegador interno", Cat.APP_CACHE, "Steam", S,
             "Cache web do cliente Steam (loja, comunidade).", REC_CLOSE_APP, CONTENTS,
             [r"%LOCALAPPDATA%\Steam\htmlcache", r"%ProgramFiles(x86)%\Steam\appcache\httpcache",
              r"%ProgramFiles%\Steam\appcache\httpcache"]),
        rule("app.steam.logs", "Steam — logs e despejos", Cat.SYSTEM_LOGS, "Steam", S,
             "Logs e despejos de falha do cliente Steam.", REC_CLOSE_APP, CONTENTS,
             [r"%ProgramFiles(x86)%\Steam\logs", r"%ProgramFiles(x86)%\Steam\dumps",
              r"%ProgramFiles%\Steam\logs", r"%ProgramFiles%\Steam\dumps"]),
        rule("app.steam.shadercache", "Steam — cache de shaders dos jogos", Cat.GPU_CACHE, "Steam", RV,
             "Shaders pré-compilados dos jogos Steam. São recriados, mas os jogos podem demorar para abrir "
             "e travar um pouco nas primeiras partidas.",
             "Revise: limpe apenas se precisar de espaço ou se um jogo apresentar problemas gráficos.", CONTENTS,
             [r"%ProgramFiles(x86)%\Steam\steamapps\shadercache", r"%ProgramFiles%\Steam\steamapps\shadercache"]),
        rule("app.epic.webcache", "Epic Games Launcher — cache web", Cat.APP_CACHE, "Epic Games", S,
             "Cache web do Epic Games Launcher.", REC_CLOSE_APP, CONTENTS,
             [r"%LOCALAPPDATA%\EpicGamesLauncher\Saved\webcache*"]),
        rule("app.epic.logs", "Epic Games Launcher — logs", Cat.SYSTEM_LOGS, "Epic Games", S,
             "Logs do Epic Games Launcher.", REC_CLOSE_APP, CONTENTS,
             [r"%LOCALAPPDATA%\EpicGamesLauncher\Saved\Logs"]),
        # GPU
        rule("gpu.nvidia", "NVIDIA — cache de shaders", Cat.GPU_CACHE, "NVIDIA", S,
             "Shaders DirectX/OpenGL/CUDA compilados pelo driver NVIDIA. Recriados automaticamente.",
             "Seguro. Jogos podem demorar um pouco mais na primeira abertura.", CONTENTS,
             [r"%LOCALAPPDATA%\NVIDIA\DXCache", r"%LOCALAPPDATA%\NVIDIA\GLCache", r"%APPDATA%\NVIDIA\ComputeCache",
              r"%LOCALAPPDATA%\NVIDIA Corporation\NV_Cache", r"%ProgramData%\NVIDIA Corporation\NV_Cache",
              r"%USERPROFILE%\AppData\LocalLow\NVIDIA\PerDriverVersion\DXCache",
              r"%USERPROFILE%\AppData\LocalLow\NVIDIA\PerDriverVersion\GLCache"]),
        rule("gpu.amd", "AMD — cache de shaders", Cat.GPU_CACHE, "AMD", S,
             "Shaders compilados pelo driver AMD. Recriados automaticamente.",
             "Seguro. Jogos podem demorar um pouco mais na primeira abertura.", CONTENTS,
             [r"%LOCALAPPDATA%\AMD\DxCache", r"%LOCALAPPDATA%\AMD\DxcCache", r"%LOCALAPPDATA%\AMD\GLCache",
              r"%LOCALAPPDATA%\AMD\VkCache", r"%LOCALAPPDATA%\AMD\OglCache"]),
        rule("gpu.intel", "Intel — cache de shaders", Cat.GPU_CACHE, "Intel", S,
             "Shaders compilados pelo driver gráfico Intel.", "Seguro.", CONTENTS,
             [r"%USERPROFILE%\AppData\LocalLow\Intel\ShaderCache"]),
        # Mídia/criação
        rule("app.capcut.cache", "CapCut — cache", Cat.APP_CACHE, "CapCut", S,
             "Cache de mídia, efeitos e prévias do CapCut. Projetos (CapCut Drafts) não são tocados.",
             REC_CLOSE_APP, CONTENTS, [r"%LOCALAPPDATA%\CapCut\User Data\Cache"]),
        rule("app.adobe.media_cache", "Adobe — cache de mídia", Cat.APP_CACHE, "Adobe", S,
             "Media Cache do Premiere/After Effects/Media Encoder (arquivos de áudio conformado e índices).",
             "Seguro com os apps da Adobe fechados; os arquivos são recriados ao abrir os projetos.", CONTENTS,
             [r"%APPDATA%\Adobe\Common\Media Cache Files", r"%APPDATA%\Adobe\Common\Media Cache",
              r"%APPDATA%\Adobe\Common\Peak Files"]),
        rule("app.roblox.logs", "Roblox — logs", Cat.SYSTEM_LOGS, "Roblox", S, "Logs do Roblox.", REC_CLOSE_APP,
             CONTENTS, [r"%LOCALAPPDATA%\Roblox\logs"]),
        rule("app.zoom.logs", "Zoom — logs", Cat.SYSTEM_LOGS, "Zoom", S, "Logs do Zoom.", REC_CLOSE_APP,
             CONTENTS, [r"%APPDATA%\Zoom\logs", r"%APPDATA%\Zoom\data\WebviewCache"]),
        rule("app.discord.logs", "Discord — logs e despejos", Cat.SYSTEM_LOGS, "Discord", S,
             "Logs e relatórios de falha do Discord.", REC_CLOSE_APP, CONTENTS,
             [r"%APPDATA%\discord\logs", r"%APPDATA%\discord\Crashpad\reports"]),
        rule("app.squirrel_temp", "Temporários de instaladores Squirrel", Cat.WINDOWS_TEMP, "Squirrel", S,
             "Restos de atualizações de apps Electron (SquirrelTemp).", "Seguro.", CONTENTS,
             [r"%LOCALAPPDATA%\SquirrelTemp"]),
        rule("app.office_cache", "Microsoft Office — cache de documentos", Cat.APP_CACHE, "Microsoft Office", RV,
             "Cache de arquivos do Office (OfficeFileCache). Pode conter alterações ainda não sincronizadas "
             "com o OneDrive/SharePoint.",
             "Revise: só limpe com o Office fechado e todos os arquivos sincronizados.", CONTENTS,
             [r"%LOCALAPPDATA%\Microsoft\Office\16.0\OfficeFileCache"]),
        rule("app.onedrive_logs", "OneDrive — logs", Cat.SYSTEM_LOGS, "OneDrive", S, "Logs do OneDrive.",
             "Seguro.", CONTENTS, [r"%LOCALAPPDATA%\Microsoft\OneDrive\logs"]),
    ]
    return out
