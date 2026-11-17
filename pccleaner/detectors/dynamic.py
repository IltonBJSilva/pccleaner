"""Achados dinâmicos: versões antigas de apps e possíveis resíduos de programas desinstalados."""
from __future__ import annotations

import logging
import os
import re
import sys
import time
from typing import Iterable

from pccleaner.core.models import CancelToken, Category as Cat, Finding, Rule

from ._base import RV, S, WHOLE, finding_from_rule, rule

_VER_RE = re.compile(r"^\d+(\.\d+)+$")

CAPCUT_RULE = rule("dynamic.capcut_old_version", "CapCut — versão antiga", Cat.OLD_VERSIONS, "CapCut", S,
                   "Versão antiga do CapCut mantida após atualização. Apenas a versão mais recente é usada.",
                   "Seguro: a versão mais recente é preservada. Feche o CapCut antes de limpar.", WHOLE)
SQUIRREL_RULE = rule("dynamic.squirrel_old_version", "Versão antiga de aplicativo", Cat.OLD_VERSIONS, "", S,
                     "Versão antiga de um app (instalador Squirrel: pastas app-x.y.z). Apenas a mais recente é usada.",
                     "Seguro: a versão mais recente é preservada. Feche o aplicativo antes de limpar.", WHOLE)
LEFTOVER_RULE = rule("dynamic.leftover", "Possível resíduo de programa", Cat.LEFTOVERS, "Desconhecido", RV,
                     "Pasta grande cujo nome não corresponde a nenhum programa instalado — possível resíduo, confirme.",
                     "Revise com cuidado: confirme que o programa foi realmente desinstalado e que a pasta não "
                     "contém dados seus (saves de jogos, projetos, configurações) antes de remover.", WHOLE)

LEFTOVER_MIN_BYTES = 50 * 1024 * 1024
LEFTOVER_MIN_IDLE_DAYS = 30


def parse_version(s: str) -> tuple[int, ...] | None:
    s = s.strip()
    if not _VER_RE.match(s):
        return None
    return tuple(int(x) for x in s.split("."))


def _subdirs(path: str) -> list[os.DirEntry]:
    from pccleaner.scanner.fs import entry_is_link
    out = []
    try:
        with os.scandir(path) as it:
            for e in it:
                try:
                    if e.is_dir(follow_symlinks=False) and not entry_is_link(e):
                        out.append(e)
                except OSError:
                    continue
    except OSError:
        pass
    return out


def _old_versions(versions: list[tuple[tuple[int, ...], str]]) -> list[str]:
    """Recebe [(versão, caminho)] e devolve os caminhos de todas exceto a mais nova."""
    if len(versions) < 2:
        return []
    versions.sort(key=lambda v: v[0])
    return [p for _v, p in versions[:-1]]


def capcut_old_versions(cancel: CancelToken | None = None) -> list[Finding]:
    from pccleaner.scanner.fs import measure_tree
    la = os.environ.get("LOCALAPPDATA")
    if not la:
        return []
    base = os.path.join(la, "CapCut", "Apps")
    if not os.path.isdir(base):
        return []
    vers = []
    for e in _subdirs(base):
        v = parse_version(e.name)
        if v is not None:
            vers.append((v, e.path))
    newest = max(vers)[1] if vers else ""
    out = []
    for p in _old_versions(vers):
        if cancel is not None and cancel.cancelled:
            break
        b, n, m = measure_tree(p, cancel)
        if b > 0:
            out.append(finding_from_rule(CAPCUT_RULE, p, b, n, m,
                                         name=f"CapCut — versão antiga {os.path.basename(p)}",
                                         reason=CAPCUT_RULE.reason + f" Versão mantida: {os.path.basename(newest)}."))
    return out


def squirrel_old_versions(cancel: CancelToken | None = None) -> list[Finding]:
    from pccleaner.scanner.fs import measure_tree
    la = os.environ.get("LOCALAPPDATA")
    if not la or not os.path.isdir(la):
        return []
    out: list[Finding] = []
    for app in _subdirs(la):
        if cancel is not None and cancel.cancelled:
            break
        # Marcador do Squirrel: Update.exe ao lado das pastas app-x.y.z
        if not os.path.isfile(os.path.join(app.path, "Update.exe")):
            continue
        vers = []
        for e in _subdirs(app.path):
            if e.name.lower().startswith("app-"):
                v = parse_version(e.name[4:])
                if v is not None:
                    vers.append((v, e.path))
        newest = max(vers)[1] if vers else ""
        for p in _old_versions(vers):
            b, n, m = measure_tree(p, cancel)
            if b > 0:
                f = finding_from_rule(SQUIRREL_RULE, p, b, n, m,
                                      name=f"{app.name} — versão antiga {os.path.basename(p)[4:]}",
                                      reason=SQUIRREL_RULE.reason + f" Versão mantida: {os.path.basename(newest)}.")
                f.app = app.name
                out.append(f)
    return out


# ---------------------------------------------------------------- resíduos

_SKIP_NAMES = {
    "microsoft", "windows", "packages", "temp", "tmp", "programs", "publishers", "comms",
    "connecteddevicesplatform", "crashdumps", "d3dscache", "virtualstore", "placeholdertilelogofolder",
    "peerdistrepub", "temporary internet files", "history", "histórico", "application data",
    "dados de aplicativos", "fontconfig", "squirreltemp", "pccleaner", "package cache", "ssh",
    "usoshared", "usoprivate", "softwaredistribution", "windowsholographicdevices", "microsoft help",
    "desktop", "documents", "start menu", "templates", "nvidia", "nvidia corporation", "intel", "amd",
    "realtek", "mozilla", "google", "apple", "apple computer", "adobe", "oracle", "cache", "caches", "pip",
    "uv", "npm", "npm-cache", "yarn", "pnpm", "pnpm-cache", "node-gyp", "jetbrains", "docker", "unity",
    "unrealengine", "steam", "nuget", "go-build", "pypa", "pypoetry", "electron", "electron-builder",
    "cypress", "deno", "composer", "typescript", "python", "chocolatey", "scoop", "winget", "wsl", "common",
    "identities", "crypto", "credentials", "protect", "systemcertificates", "vault", "regid.1991-06.com.microsoft",
    "sentry", "cef", "logs", "log", "backup", "onedrive", "dbg", "speech", "ms-playwright", "ms-playwright-go",
    "ms-playwright-mcp", "prisma-nodejs", "iconcache.db", "packagemanagement", "windowsapps",
    "mozilla firefox", "tailscale", "openai", "anthropic", "claude", "claude code",
}
_SKIP_PREFIXES = ("microsoft", "windows", "{", ".", "ms-", "msteams", "regid.")


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _installed_names() -> set[str]:
    """Nomes normalizados de programas instalados: registro Uninstall, Program Files, menu Iniciar e AppX."""
    names: set[str] = set()

    def add(s: str | None) -> None:
        if s:
            n = _norm(s)
            if len(n) >= 3:
                names.add(n)

    if sys.platform == "win32":
        import winreg
        sub = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        sources = [(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
                   (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
                   (winreg.HKEY_CURRENT_USER, 0)]
        for hive, flag in sources:
            try:
                root = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | flag)
            except OSError:
                continue
            with root:
                i = 0
                while True:
                    try:
                        kname = winreg.EnumKey(root, i)
                    except OSError:
                        break
                    i += 1
                    add(kname)
                    try:
                        with winreg.OpenKey(root, kname) as k:
                            for val in ("DisplayName", "Publisher", "InstallLocation", "DisplayIcon"):
                                try:
                                    v, _t = winreg.QueryValueEx(k, val)
                                except OSError:
                                    continue
                                if not isinstance(v, str) or not v:
                                    continue
                                if val in ("InstallLocation", "DisplayIcon"):
                                    v = v.split(",")[0].strip().strip('"')
                                    if val == "DisplayIcon":
                                        v = os.path.dirname(v)
                                    for p in [p for p in re.split(r"[\\/]", v) if p][1:]:
                                        add(p)
                                else:
                                    add(v)
                    except OSError:
                        continue
    env = os.environ
    la = env.get("LOCALAPPDATA", "")
    for base in (env.get("ProgramFiles"), env.get("ProgramFiles(x86)"), env.get("ProgramW6432"),
                 os.path.join(la, "Programs") if la else None):
        if base and os.path.isdir(base):
            try:
                for n in os.listdir(base):
                    add(n)
            except OSError:
                pass
    for base in (os.path.join(env.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs"),
                 os.path.join(env.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs")):
        if os.path.isdir(base):
            for _root, dirs, files in os.walk(base):
                for n in dirs:
                    add(n)
                for n in files:
                    add(os.path.splitext(n)[0])
    pk = os.path.join(la, "Packages")
    if la and os.path.isdir(pk):
        try:
            for n in os.listdir(pk):
                base = n.split("_")[0]
                for part in base.split("."):
                    add(part)
                add(base)
        except OSError:
            pass
    return names


def _known_rule_prefixes(rules: Iterable[Rule]) -> list[str]:
    """Prefixos fixos (antes do primeiro curinga) dos caminhos das regras, normalizados."""
    out = []
    for r in rules:
        for p in r.paths:
            e = os.path.expandvars(p)
            if "%" in e:
                continue
            fixed = []
            for s in e.split("\\"):
                if any(c in s for c in "*?["):
                    break
                fixed.append(s)
            if fixed:
                out.append(os.path.normcase(os.path.normpath("\\".join(fixed))))
    return out


def name_matches_installed(folder_name: str, installed: set[str]) -> bool:
    f = _norm(folder_name)
    if len(f) < 3:
        return True   # nomes curtos demais: não arriscar
    for s in installed:
        if f in s:
            return True
        if len(s) >= 5 and s in f:
            return True
    return False


def _skip_name(name: str) -> bool:
    low = name.lower()
    if low in _SKIP_NAMES or low.startswith(_SKIP_PREFIXES):
        return True
    return bool(re.fullmatch(r"[0-9a-f\-]{16,}", low))   # GUID/hash


def leftover_findings(cancel: CancelToken | None = None, installed: set[str] | None = None,
                      rules: Iterable[Rule] | None = None, bases: list[str] | None = None) -> list[Finding]:
    from pccleaner.scanner.fs import measure_tree
    if installed is None:
        installed = _installed_names()
    if rules is None:
        from . import all_rules
        rules = all_rules()
    prefixes = _known_rule_prefixes(rules)
    if bases is None:
        env = os.environ
        bases = [b for b in (env.get("LOCALAPPDATA"), env.get("APPDATA"), env.get("ProgramData")) if b]
    now = time.time()
    out: list[Finding] = []
    for base in bases:
        for e in _subdirs(base):
            if cancel is not None and cancel.cancelled:
                return out
            if _skip_name(e.name) or name_matches_installed(e.name, installed):
                continue
            n = os.path.normcase(os.path.normpath(e.path))
            # Pastas que contêm (ou são) locais de regras conhecidas não são resíduos.
            if any(p == n or p.startswith(n + "\\") or n.startswith(p + "\\") for p in prefixes):
                continue
            b, cnt, newest = measure_tree(e.path, cancel)
            if b < LEFTOVER_MIN_BYTES:
                continue
            if newest is not None and now - newest < LEFTOVER_MIN_IDLE_DAYS * 86400:
                continue   # em uso recente: provavelmente pertence a algo instalado
            # mtime inválido (0/antes de 1980) não diz nada sobre o uso da pasta
            idle = int((now - newest) / 86400) if newest and newest > 315532800 else None
            f = finding_from_rule(LEFTOVER_RULE, e.path, b, cnt, newest, name=f"Possível resíduo: {e.name}")
            f.app = e.name
            if idle is not None:
                f.notes.append(f"Nenhum arquivo modificado há {idle} dias.")
            out.append(f)
    return out


def dynamic_findings(cancel: CancelToken | None = None) -> list[Finding]:
    out: list[Finding] = []
    for fn in (capcut_old_versions, squirrel_old_versions, leftover_findings):
        if cancel is not None and cancel.cancelled:
            break
        try:
            out.extend(fn(cancel))
        except Exception as e:  # um detector com problema não deve derrubar a varredura
            logging.getLogger(__name__).warning("detector dinâmico %s falhou: %s", fn.__name__, e)
    return out
