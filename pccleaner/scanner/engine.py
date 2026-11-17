"""Motor de varredura: locais conhecidos + varredura profunda + classificação."""
from __future__ import annotations

import logging
import os
import shutil
import stat
import sys
import time
import uuid
from typing import Callable

from pccleaner import classifier
from pccleaner.core.models import (CancelToken, Category, CleanMode, Finding, FolderStat, LargeFile, Rule,
                                   SafetyLevel, ScanOptions, ScanProgress, ScanResult)
from pccleaner.detectors import RECYCLE_BIN_RULE_ID, all_rules, dynamic_findings
from pccleaner.detectors._base import finding_from_rule, rule as make_rule

from .fs import disk_bytes, entry_is_link, expand_pattern, marker_present, measure_tree
from .recyclebin import query_recycle_bin

log = logging.getLogger(__name__)

ProgressCb = Callable[[ScanProgress], None]
PROGRESS_INTERVAL = 0.1
MAX_ERRORS = 500
MAX_LARGE_FILES = 2000

OLD_FILE_RULE = make_rule("deep.old_large_file", "Arquivo grande e antigo", Category.OLD_FILES, "Arquivo",
                          SafetyLevel.CAUTION,
                          "Arquivo grande que não é modificado há muito tempo.",
                          "Apenas informativo: abra a pasta e decida se ainda precisa do arquivo.", CleanMode.NONE)

# Nomes nunca percorridos na varredura profunda.
SKIP_DIR_NAMES = {"$recycle.bin", "system volume information", "$winreagent", "config.msi", "recovery",
                  "$windows.~bt", "$windows.~ws", "$sysreset", "windows.old"}
SKIP_ROOT_FILES = {"pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log", "dumpstack.log.tmp"}
# Abaixo destes nomes não casamos regras de projeto (dependências internas de ferramentas/apps/extensões),
# mas continuamos medindo tamanhos.
NO_MATCH_ZONES = {"appdata", "site-packages", ".vscode", ".cursor", ".nuget", ".m2", ".cargo", ".rustup",
                  ".gradle", "anaconda3", "miniconda3", "miniforge3", ".conda", "scoop", ".pyenv", "programdata",
                  "program files", "program files (x86)", ".git", ".vscode-insiders", ".windsurf",
                  ".antigravity", "go", ".bun", ".npm", ".pnpm-store", "extensions", "plugins"}


def _app_dir() -> str:
    """Pasta do próprio app (projeto ou executável congelado) — nunca varrida."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _norm(p: str) -> str:
    return os.path.normcase(os.path.abspath(p)).rstrip("\\/")


def _within(child_n: str, parent_n: str) -> bool:
    return child_n == parent_n or child_n.startswith(parent_n + "\\")


def _skip_roots() -> set[str]:
    env = os.environ
    s = {_norm(_app_dir())}
    for v in (env.get("SystemRoot", r"C:\Windows"), env.get("ProgramFiles"), env.get("ProgramFiles(x86)"),
              env.get("ProgramW6432")):
        if v:
            s.add(_norm(v))
    return s


class _Ctx:
    def __init__(self, progress: ProgressCb | None, cancel: CancelToken | None) -> None:
        self.cb = progress
        self.cancel = cancel or CancelToken()
        self.start = time.time()
        self.last_emit = 0.0
        self.p = ScanProgress()
        self.errors: list[str] = []
        self.error_count = 0

    @property
    def cancelled(self) -> bool:
        return self.cancel.cancelled

    def error(self, msg: str) -> None:
        self.error_count += 1
        if len(self.errors) < MAX_ERRORS:
            self.errors.append(msg)

    def emit(self, force: bool = False) -> None:
        if self.cb is None:
            return
        now = time.time()
        if not force and now - self.last_emit < PROGRESS_INTERVAL:
            return
        self.last_emit = now
        self.p.elapsed = now - self.start
        self.p.errors = self.error_count
        try:
            self.cb(ScanProgress(**{**self.p.__dict__, "categories": dict(self.p.categories)}))
        except Exception:  # callback da GUI nunca derruba a varredura
            log.exception("callback de progresso falhou")

    def add_finding(self, f: Finding) -> None:
        self.p.findings_count += 1
        key = f.category.value
        self.p.categories[key] = self.p.categories.get(key, 0) + f.size_bytes


# ---------------------------------------------------------------- fase 1

def _glob_tag(pattern: str, path: str) -> str:
    pat_parts = os.path.expandvars(pattern).split("\\")
    path_parts = path.split("\\")
    if len(pat_parts) != len(path_parts):
        return ""
    return ", ".join(pp for pt, pp in zip(pat_parts, path_parts) if "*" in pt or "?" in pt)


def _phase_known(rules: list[Rule], ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    path_rules = [r for r in rules if r.paths or r.id == RECYCLE_BIN_RULE_ID]
    total = len(path_rules) + 1   # +1 = detectores dinâmicos
    ctx.p.phase = "Locais conhecidos"
    for i, r in enumerate(path_rules):
        if ctx.cancelled:
            return findings
        ctx.p.percent = round(100.0 * i / total, 1)
        if r.id == RECYCLE_BIN_RULE_ID:
            ctx.p.current_path = "Lixeira"
            ctx.emit()
            size, items = query_recycle_bin(None)
            if size > 0:
                path = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "$Recycle.Bin")
                f = finding_from_rule(r, path, size, items, None)
                findings.append(f)
                ctx.add_finding(f)
            continue
        seen: set[str] = set()
        dirs_only = r.clean_mode is CleanMode.CONTENTS
        for pattern in r.paths:
            for path in expand_pattern(pattern, dirs_only=dirs_only):
                if ctx.cancelled:
                    return findings
                n = _norm(path)
                if n in seen:
                    continue
                seen.add(n)
                ctx.p.current_path = path
                ctx.emit()
                b, cnt, newest = measure_tree(path, ctx.cancel, r.min_age_days)
                if b <= 0:
                    continue
                name = r.name
                if r.category is Category.INSTALLERS:
                    name = f"{r.name}: {os.path.basename(path)}"
                elif "*" in pattern and r.category is not Category.THUMBNAILS:
                    tag = _glob_tag(pattern, path)   # identifica o perfil casado (ex.: "Profile 1")
                    if tag:
                        name = f"{r.name} ({tag})"
                f = finding_from_rule(r, path, b, cnt, newest, name=name)
                findings.append(f)
                ctx.add_finding(f)
    if ctx.cancelled:
        return findings
    ctx.p.current_path = "Versões antigas e resíduos de programas"
    ctx.p.percent = round(100.0 * len(path_rules) / total, 1)
    ctx.emit(force=True)
    for f in dynamic_findings(ctx.cancel):
        findings.append(f)
        ctx.add_finding(f)
    return findings


# ---------------------------------------------------------------- fase 2

class _DeepIndex:
    def __init__(self, rules: list[Rule]) -> None:
        self.by_name: dict[str, list[Rule]] = {}
        for r in rules:
            for n in r.dir_names:
                self.by_name.setdefault(n.lower(), []).append(r)

    def match(self, name_lower: str, parent_path: str, parent_name_lower: str,
              sibling_names: set[str]) -> Rule | None:
        for r in self.by_name.get(name_lower, ()):
            if r.parent_names and parent_name_lower not in {p.lower() for p in r.parent_names}:
                continue
            if r.sibling_markers and not any(marker_present(parent_path, m, sibling_names)
                                             for m in r.sibling_markers):
                continue
            return r
        return None


def _add_size(top: dict[str, list], k1: str | None, k2: str | None, b: int, cnt: int,
              mtime: float | None) -> None:
    for k in (k1, k2):
        if k is None:
            continue
        rec = top.get(k)
        if rec is None:
            top[k] = [b, cnt, mtime]
        else:
            rec[0] += b
            rec[1] += cnt
            if mtime is not None and (rec[2] is None or mtime > rec[2]):
                rec[2] = mtime


def _phase_deep(options: ScanOptions, rules: list[Rule], ctx: _Ctx, findings: list[Finding],
                top: dict[str, list], large: list[LargeFile]) -> None:
    roots = options.roots or [os.environ.get("USERPROFILE") or os.path.expanduser("~")]
    roots = [r for r in roots if r and os.path.isdir(r)]
    index = _DeepIndex(rules)
    skip_roots = _skip_roots()
    threshold = max(1, int(options.large_file_threshold_mb)) * 1024 * 1024
    ctx.p.phase = "Varredura profunda"
    ctx.p.percent = -1.0

    # Estimativa de progresso: só faz sentido quando as raízes são unidades inteiras.
    used_total = 0
    if all(len(_norm(r)) <= 3 for r in roots):
        for r in roots:
            try:
                used_total += shutil.disk_usage(r).used
            except OSError:
                pass
    start_bytes = ctx.p.bytes_scanned

    visited_roots: list[str] = []
    for root in roots:
        rn = _norm(root)
        if any(_within(rn, v) for v in visited_roots) or any(_within(rn, s) for s in skip_roots):
            continue
        visited_roots.append(rn)
        root_is_drive = len(rn) <= 3
        # pilha: (caminho, profundidade, chave nível 1, chave nível 2, em zona sem casamento)
        stack: list[tuple[str, int, str | None, str | None, bool]] = [(root, 0, None, None, False)]
        files_since_check = 0
        while stack:
            if ctx.cancelled:
                return
            path, depth, k1, k2, nomatch = stack.pop()
            ctx.p.current_path = path
            try:
                with os.scandir(path) as it:
                    entries = list(it)
            except OSError as e:
                ctx.error(f"{path}: {e.strerror or e}")
                continue
            names_lower = {e.name.lower() for e in entries}
            parent_name_lower = os.path.basename(path.rstrip("\\")).lower()
            for e in entries:
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError as ex:
                    ctx.error(f"{e.path}: {ex.strerror or ex}")
                    continue
                if entry_is_link(e, st):
                    continue
                low = e.name.lower()
                if stat.S_ISDIR(st.st_mode):
                    if low in SKIP_DIR_NAMES or _norm(e.path) in skip_roots:
                        continue
                    # chaves de agregação para top_folders: nível 1 e nível 2 abaixo da raiz
                    ck1 = k1 if depth >= 1 else e.path
                    ck2 = k2 if depth >= 2 else (e.path if depth == 1 else None)
                    child_nomatch = nomatch or low in NO_MATCH_ZONES
                    r = None if nomatch else index.match(low, path, parent_name_lower, names_lower)
                    if r is not None:
                        b, cnt, newest = measure_tree(e.path, ctx.cancel, r.min_age_days)
                        _add_size(top, ck1, ck2, b, cnt, newest)
                        ctx.p.files_scanned += cnt
                        ctx.p.bytes_scanned += b
                        if b > 0:
                            proj = os.path.basename(path.rstrip("\\")) or path
                            f = finding_from_rule(r, e.path, b, cnt, newest, name=f"{r.name} — {proj}")
                            findings.append(f)
                            ctx.add_finding(f)
                        ctx.emit()
                        continue
                    stack.append((e.path, depth + 1, ck1, ck2, child_nomatch))
                else:
                    if root_is_drive and depth == 0 and low in SKIP_ROOT_FILES:
                        continue
                    size = disk_bytes(st)
                    ctx.p.files_scanned += 1
                    ctx.p.bytes_scanned += size
                    if depth >= 1:
                        _add_size(top, k1, k2, size, 1, st.st_mtime)
                    if size >= threshold:
                        large.append(LargeFile(e.path, size, st.st_mtime, st.st_atime))
                        if len(large) > MAX_LARGE_FILES * 2:
                            large.sort(key=lambda x: x.size_bytes, reverse=True)
                            del large[MAX_LARGE_FILES:]
                    files_since_check += 1
                    if files_since_check >= 2000:
                        files_since_check = 0
                        if ctx.cancelled:
                            return
                        ctx.emit()
            if used_total:
                ctx.p.percent = min(99.0, round(100.0 * (ctx.p.bytes_scanned - start_bytes) / used_total, 1))
            ctx.emit()


# ---------------------------------------------------------------- dedupe

def dedupe_findings(findings: list[Finding], rule_order: dict[str, int] | None = None) -> list[Finding]:
    """Remove duplicados e itens aninhados.

    - Mesmo caminho: fica o de maior rank de segurança (mais cauteloso); empate -> regra declarada antes.
    - Item limpável dentro de outro item limpável: se o externo é tão ou mais cauteloso, o interno é
      descartado (já está coberto). Se o interno é mais cauteloso, ambos ficam, o tamanho do interno é
      descontado do externo (não conta em dobro) e o externo recebe uma nota.
    - Itens informativos (NONE/COMMAND) nunca absorvem outros.
    """
    order = rule_order or {}
    best: dict[str, Finding] = {}
    for f in findings:
        n = _norm(f.path) if f.clean_mode is not CleanMode.RECYCLE_BIN else "::recycle::"
        cur = best.get(n)
        if cur is None:
            best[n] = f
            continue
        if f.clean_mode is CleanMode.NONE and cur.clean_mode is not CleanMode.NONE:
            continue
        if cur.clean_mode is CleanMode.NONE and f.clean_mode is not CleanMode.NONE:
            best[n] = f
            continue
        if (f.safety.rank, -order.get(f.rule_id, 10 ** 6)) > (cur.safety.rank, -order.get(cur.rule_id, 10 ** 6)):
            best[n] = f
    items = sorted(best.items(), key=lambda kv: len(kv[0]))
    kept: list[tuple[str, Finding]] = []
    for n, f in items:
        drop = False
        if f.clean_mode is not CleanMode.RECYCLE_BIN and f.cleanable:
            for pn, pf in kept:
                if not pf.cleanable or pf.clean_mode is CleanMode.RECYCLE_BIN:
                    continue
                if not n.startswith(pn + "\\"):
                    continue
                if pf.safety.rank >= f.safety.rank:
                    drop = True
                    break
                pf.size_bytes = max(0, pf.size_bytes - f.size_bytes)
                pf.file_count = max(0, pf.file_count - f.file_count)
                note = "Contém um item mais sensível listado separadamente; o tamanho dele não está somado aqui."
                if note not in pf.notes:
                    pf.notes.append(note)
        if not drop:
            kept.append((n, f))
    return [f for _n, f in kept]


# ---------------------------------------------------------------- API

def run_scan(options: ScanOptions, progress: ProgressCb | None = None,
             cancel: CancelToken | None = None) -> ScanResult:
    ctx = _Ctx(progress, cancel)
    rules = all_rules()
    rule_order = {r.id: i for i, r in enumerate(rules)}
    if not options.include_downloads:
        rules = [r for r in rules if r.category not in (Category.INSTALLERS, Category.DOWNLOADS)]
    findings: list[Finding] = []
    top: dict[str, list] = {}
    large: list[LargeFile] = []
    ctx.emit(force=True)
    try:
        findings = _phase_known(rules, ctx)
        if options.deep_scan and not ctx.cancelled:
            _phase_deep(options, rules, ctx, findings, top, large)
    except Exception as e:   # nunca perder o resultado parcial
        log.exception("erro na varredura")
        ctx.error(f"Erro inesperado na varredura: {e}")

    # Arquivos grandes e antigos -> achados informativos.
    large.sort(key=lambda x: x.size_bytes, reverse=True)
    del large[MAX_LARGE_FILES:]
    now = time.time()
    old_cutoff = now - max(0, options.old_file_days) * 86400
    for lf in large:
        if lf.mtime < old_cutoff:
            f = finding_from_rule(OLD_FILE_RULE, lf.path, lf.size_bytes, 1, lf.mtime,
                                  name=f"Arquivo grande e antigo: {os.path.basename(lf.path)}")
            f.notes.append(f"Não modificado há {int((now - lf.mtime) / 86400)} dias.")
            findings.append(f)

    ctx.p.phase = "Classificação"
    ctx.p.current_path = ""
    ctx.emit(force=True)
    findings = dedupe_findings(findings, rule_order)
    for f in findings:
        try:
            classifier.classify(f)
            f.selected = classifier.default_selected(f)
        except Exception as e:
            log.exception("falha ao classificar %s", f.path)
            f.safety = SafetyLevel.PROTECTED
            f.selected = False
            f.notes.append(f"Erro na classificação: {e}")
    findings.sort(key=lambda f: f.size_bytes, reverse=True)

    top_list = [FolderStat(k, v[0], v[1], v[2]) for k, v in top.items()]
    top_list.sort(key=lambda s: s.size_bytes, reverse=True)
    top_list = top_list[:max(0, options.top_folders)]

    ctx.p.findings_count = len(findings)
    ctx.p.categories = {}
    for f in findings:
        ctx.p.categories[f.category.value] = ctx.p.categories.get(f.category.value, 0) + f.size_bytes
    if not ctx.cancelled:
        ctx.p.percent = 100.0
    ctx.p.phase = "Cancelado" if ctx.cancelled else "Concluído"
    ctx.emit(force=True)
    return ScanResult(scan_id=uuid.uuid4().hex, started_at=ctx.start, finished_at=time.time(), findings=findings,
                      top_folders=top_list, large_files=large, files_scanned=ctx.p.files_scanned,
                      bytes_scanned=ctx.p.bytes_scanned, errors=ctx.errors, cancelled=ctx.cancelled)
