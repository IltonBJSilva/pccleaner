"""Motor de limpeza.

Segurança (não negociável):
- Antes de tocar em qualquer coisa, cada finding passa por `safe_fs.assert_independent_root`
  (checagens próprias: X:\\ completo, profundidade >= 2, não raiz de drive, não cwd/ancestral do
  cwd, não pasta do app) E por `security.assert_target_root_allowed`. Falhou -> item ignorado com erro.
- TODA exclusão passa por `security.assert_deletable(alvo, finding.path, allow_scope_root=...)`.
- Links/junções internos são removidos como link, nunca seguidos; raiz que é link é recusada.
- CONTENTS nunca remove a própria pasta do finding.

Critério de quarentena (risco reversível):
- WHOLE: quarentena se `use_quarantine` e tamanho <= `quarantine_max_bytes`.
- CONTENTS: itens SAFE (cache regenerável) são apagados direto; apenas REVIEW/CAUTION vão para a
  quarentena (arquivo a arquivo) se o tamanho do finding <= `quarantine_max_bytes`.
- Lixeira: API do shell (irreversível); não usa o caminho do finding.
Um lote de quarentena por chamada a `clean()`. Bytes movidos para a quarentena contam em
`freed_bytes` (com `quarantined=True`); o espaço só é liberado ao purgar o lote.
"""
from __future__ import annotations

import ctypes
import logging
import os
import stat
import sys
import time
from typing import Callable

from pccleaner.cleaner import safe_fs
from pccleaner.core import security
from pccleaner.core.models import (CancelToken, Category, CleanItemResult, CleanMode, CleanReport,
                                   Finding, SafetyLevel, human_size, now)

log = logging.getLogger("pccleaner.cleaner")

DEFAULT_QUARANTINE_MAX = 2 * 1024 ** 3
_PROGRESS_INTERVAL = 0.05
ProgressFn = Callable[[str, int, int], None]


class _SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint32), ("i64Size", ctypes.c_int64), ("i64NumItems", ctypes.c_int64)]
    if ctypes.sizeof(ctypes.c_void_p) == 4:
        _pack_ = 1


SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND = 0x1, 0x2, 0x4


def recycle_bin_info() -> tuple[int, int]:
    """(bytes, itens) de todas as lixeiras. Somente leitura."""
    if sys.platform != "win32":
        return 0, 0
    info = _SHQUERYRBINFO()
    info.cbSize = ctypes.sizeof(info)
    hr = ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
    if hr != 0:
        raise OSError(f"SHQueryRecycleBinW falhou (HRESULT 0x{hr & 0xFFFFFFFF:08X})")
    return int(info.i64Size), int(info.i64NumItems)


def empty_recycle_bin() -> None:
    if sys.platform != "win32":
        raise OSError("Lixeira só é suportada no Windows")
    hr = ctypes.windll.shell32.SHEmptyRecycleBinW(
        None, None, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND)
    if hr != 0 and (hr & 0xFFFFFFFF) != 0x8000FFFF:   # E_UNEXPECTED = já vazia
        raise OSError(f"SHEmptyRecycleBinW falhou (HRESULT 0x{hr & 0xFFFFFFFF:08X})")


class _Ctx:
    def __init__(self, use_quarantine, qmax, progress, cancel, total, qm) -> None:
        self.use_quarantine, self.qmax = use_quarantine, qmax
        self.progress, self.cancel, self.total = progress, cancel, total
        self.done = 0
        self._qm = qm
        self.batch_id: str | None = None
        self._last = 0.0

    def quarantine(self):
        if self._qm is None:
            from pccleaner.quarantine.manager import QuarantineManager   # import tardio (evita ciclo)
            self._qm = QuarantineManager()
        if self.batch_id is None:
            self.batch_id = self._qm.new_batch()
        return self._qm, self.batch_id

    def tick(self, path: str, force: bool = False) -> None:
        if self.progress is None:
            return
        t = time.monotonic()
        if force or t - self._last >= _PROGRESS_INTERVAL:
            self._last = t
            try:
                self.progress(path, self.done, self.total)
            except Exception:
                log.exception("Erro no callback de progresso")

    @property
    def cancelled(self) -> bool:
        return self.cancel is not None and self.cancel.cancelled


def clean(findings: list[Finding], *, use_quarantine: bool = True,
          quarantine_max_bytes: int = DEFAULT_QUARANTINE_MAX,
          progress: ProgressFn | None = None,
          cancel: CancelToken | None = None,
          quarantine_manager=None) -> CleanReport:
    """Limpa os findings. `quarantine_manager` (opcional) substitui o QuarantineManager padrão."""
    started = now()
    ctx = _Ctx(use_quarantine, quarantine_max_bytes, progress, cancel, len(findings), quarantine_manager)
    items: list[CleanItemResult] = []
    cancelled = False
    for f in findings:
        if ctx.cancelled:
            cancelled = True
            break
        ctx.tick(f.path, force=True)
        res = CleanItemResult(finding_id=f.id, path=f.path)
        items.append(res)
        stats = safe_fs.WalkStats()
        try:
            _clean_one(f, res, stats, ctx)
        except security.UnsafePathError as exc:
            stats.add_error(f"Recusado por segurança: {exc}")
            log.warning("Recusado por segurança: %s", exc)
        except FileNotFoundError:
            pass
        except OSError as exc:
            stats.add_error(f"Erro: {exc}")
            log.warning("Erro ao limpar %s: %s", f.path, exc)
        res.freed_bytes += stats.freed
        res.files_removed += stats.removed
        res.files_skipped += stats.skipped
        res.errors.extend(stats.finalize_errors())
        ctx.done += 1
        if stats.cancelled or ctx.cancelled:
            cancelled = True
            break
    ctx.tick("", force=True)
    report = CleanReport(started_at=started, finished_at=now(), items=items, cancelled=cancelled)
    log.info("Limpeza concluída: %s, %d arquivo(s), %d erro(s)%s", human_size(report.freed_bytes),
             report.files_removed, report.error_count, " (cancelada)" if cancelled else "")
    return report


def _clean_one(f: Finding, res: CleanItemResult, stats: safe_fs.WalkStats, ctx: _Ctx) -> None:
    if f.safety is SafetyLevel.PROTECTED or not f.cleanable:
        why = "protegido" if f.safety is SafetyLevel.PROTECTED else "limpeza manual"
        hint = f" — sugestão: {f.command_hint}" if f.command_hint else ""
        stats.add_error(f"Não executado ({why}): {f.name}{hint}")
        return

    if f.clean_mode is CleanMode.RECYCLE_BIN:
        size, count = recycle_bin_info()
        if count or size:
            empty_recycle_bin()
            stats.freed += size
            stats.removed += count
            log.info("Lixeira esvaziada: %s, %d item(ns)", human_size(size), count)
        return

    # Defesa em profundidade: checagens próprias + security, ANTES de qualquer acesso.
    safe_fs.assert_independent_root(f.path)
    security.assert_target_root_allowed(f.path)
    if not os.path.lexists(f.path):
        return
    if security.is_reparse_point(f.path):
        raise security.UnsafePathError(f"Raiz do item é link/junção — ignorada: {f.path}")

    if f.clean_mode is CleanMode.CONTENTS:
        if not stat.S_ISDIR(os.lstat(f.path).st_mode):
            raise security.UnsafePathError(f"Modo 'conteúdo' exige uma pasta: {f.path}")
        cutoff = time.time() - f.min_age_days * 86400 if f.min_age_days > 0 else None
        action = None
        if (ctx.use_quarantine and f.safety in (SafetyLevel.REVIEW, SafetyLevel.CAUTION)
                and f.size_bytes <= ctx.qmax):
            action = _store_action(ctx, res)
        safe_fs.process_tree(f.path, f.path, stats, cutoff=cutoff, file_action=action,
                             cancel=ctx.cancel, on_file=ctx.tick)
    elif f.clean_mode is CleanMode.WHOLE:
        _clean_whole(f, res, stats, ctx)


def _store_action(ctx: _Ctx, res: CleanItemResult) -> safe_fs.FileAction:
    def action(p: str) -> int:
        size = os.lstat(p).st_size
        qm, batch = ctx.quarantine()
        qm.store(batch, p)
        res.quarantined = True
        return size
    return action


def _clean_whole(f: Finding, res: CleanItemResult, stats: safe_fs.WalkStats, ctx: _Ctx) -> None:
    security.assert_deletable(f.path, f.path, allow_scope_root=True)
    if security.norm(f.path) in security.protected_exact():
        raise security.UnsafePathError(f"Caminho protegido: {f.path}")
    is_dir = stat.S_ISDIR(os.lstat(f.path).st_mode)
    size, _ = safe_fs.tree_size(f.path)

    if not (ctx.use_quarantine and size <= ctx.qmax):
        safe_fs.delete_path(f.path, f.path, stats, cancel=ctx.cancel)
        return

    qm, batch = ctx.quarantine()
    if not is_dir:
        try:
            qm.store(batch, f.path)
        except PermissionError as exc:
            stats.skipped += 1
            why = "em uso por outro programa" if safe_fs.is_lock_error(exc) else "acesso negado"
            stats.add_error(f"Ignorado ({why}): {f.path}")
            return
        stats.freed += size
        stats.removed += 1
        res.quarantined = True
        return

    ok, nfiles = _tree_fully_deletable(f.path) if _same_volume(f.path, str(qm.base_dir)) else (False, 0)
    if ok:
        try:
            qm.store(batch, f.path)   # um único rename da pasta inteira
            stats.freed += size
            stats.removed += nfiles
            res.quarantined = True
            return
        except PermissionError:
            log.info("Pasta em uso, quarentena arquivo a arquivo: %s", f.path)
    safe_fs.process_tree(f.path, f.path, stats, file_action=_store_action(ctx, res),
                         cancel=ctx.cancel, on_file=ctx.tick)
    if stats.cancelled:
        return
    try:
        security.assert_deletable(f.path, f.path, allow_scope_root=True)
        if not safe_fs.remove_empty_dir(f.path):
            stats.add_error(f"Pasta mantida (contém itens preservados/em uso): {f.path}")
    except OSError as exc:
        stats.add_error(f"Não foi possível remover a pasta {f.path}: {exc}")


def _same_volume(a: str, b: str) -> bool:
    return os.path.splitdrive(os.path.abspath(a))[0].lower() == os.path.splitdrive(os.path.abspath(b))[0].lower()


def _tree_fully_deletable(root: str) -> tuple[bool, int]:
    """(ok, nº de arquivos): ok=True se todo item interno passa em assert_deletable."""
    files = 0
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError:
            return False, 0
        for e in entries:
            try:
                security.assert_deletable(e.path, root, allow_scope_root=False)
            except security.UnsafePathError:
                return False, 0
            if not security.is_reparse_point(e.path) and e.is_dir(follow_symlinks=False):
                stack.append(e.path)
            else:
                files += 1
    return True, files


_BROWSER_HINTS = ("chrome", "edge", "firefox", "brave", "opera", "vivaldi", "navegador")
_AI_HINTS = ("hugging", "ollama", "lm studio", "lmstudio", "torch", "modelo", "model", "stable diffusion",
             "comfy", "whisper", "gpt4all", "llama")
_CLOSE_APP_CATEGORIES = {Category.BROWSER_CACHE, Category.APP_CACHE, Category.GPU_CACHE}


def preview_consequences(findings: list[Finding], *, use_quarantine: bool = True,
                         quarantine_max_bytes: int = DEFAULT_QUARANTINE_MAX) -> list[str]:
    """Avisos em pt-BR sobre o que acontecerá ao limpar `findings`."""
    msgs: list[str] = []

    def add(m: str) -> None:
        if m not in msgs:
            msgs.append(m)

    def lst(xs: list[str]) -> str:
        return ", ".join(xs[:5]) + ("..." if len(xs) > 5 else "")

    cats = {f.category for f in findings}
    close, admin, manual, big, caution, aged = [], [], [], [], [], []
    safe_direct = 0
    for f in findings:
        text = f"{f.app} {f.name} {f.rule_id}".lower()
        if not f.cleanable:
            manual.append(f.name)
            continue
        if f.category is Category.BROWSER_CACHE or any(h in f.app.lower() for h in _BROWSER_HINTS):
            add("Navegadores precisarão recarregar páginas e imagens (primeiro acesso aos sites mais lento). "
                "Senhas, cookies e histórico NÃO são apagados.")
        if any(h in text for h in _AI_HINTS):
            add("Modelos de IA serão baixados novamente quando forem usados (podem ser vários GB).")
        if f.category in _CLOSE_APP_CATEGORIES and f.app and f.app not in close:
            close.append(f.app)
        if f.requires_admin:
            admin.append(f.name)
        if f.safety is SafetyLevel.CAUTION:
            caution.append(f.name)
        if f.min_age_days > 0:
            aged.append(f"{f.name} (> {f.min_age_days} dias)")
        if f.clean_mode is CleanMode.WHOLE or (f.clean_mode is CleanMode.CONTENTS and f.safety is not SafetyLevel.SAFE):
            if use_quarantine and f.size_bytes > quarantine_max_bytes:
                big.append(f"{f.name} ({human_size(f.size_bytes)})")
        elif f.clean_mode is CleanMode.CONTENTS:
            safe_direct += 1

    per_cat = {
        Category.DEV_CACHE: "Gerenciadores de pacotes (pip, npm, NuGet, Gradle...) precisarão baixar pacotes novamente.",
        Category.DEV_DEPENDENCIES: "Projetos precisarão reinstalar dependências (ex.: npm install) antes de executar.",
        Category.BUILD_ARTIFACTS: "Projetos serão recompilados por completo no próximo build.",
        Category.THUMBNAILS: "Miniaturas do Explorer serão recriadas (pastas com imagens abrirão mais devagar na 1ª vez).",
        Category.GPU_CACHE: "Shaders serão recompilados: jogos e apps 3D podem engasgar na primeira execução.",
        Category.WINDOWS_UPDATE: "Atualizações baixadas serão removidas; pendentes podem ser baixadas novamente.",
        Category.CRASH_DUMPS: "Despejos de erro deixarão de estar disponíveis para diagnóstico.",
        Category.SYSTEM_LOGS: "Logs deixarão de estar disponíveis para diagnóstico.",
        Category.OLD_VERSIONS: "Versões antigas de aplicativos não poderão ser usadas para reverter atualizações.",
        Category.INSTALLERS: "Instaladores removidos precisarão ser baixados novamente se necessários.",
        Category.RECYCLE_BIN: "A Lixeira será esvaziada permanentemente (não passa pela quarentena).",
    }
    for c, m in per_cat.items():
        if c in cats:
            add(m)
    if close:
        add("Feche estes aplicativos antes de limpar (arquivos em uso serão ignorados): " + lst(close) + ".")
    if admin:
        add(f"{len(admin)} item(ns) exigem privilégios de administrador e podem falhar sem eles: {lst(admin)}.")
    if caution:
        add(f"{len(caution)} item(ns) marcados como 'Atenção' — revise antes de confirmar: {lst(caution)}.")
    if aged:
        add("Somente arquivos antigos serão apagados em: " + lst(aged) + ".")
    if use_quarantine:
        if big:
            add("Itens maiores que o limite da quarentena serão apagados DEFINITIVAMENTE: " + lst(big) + ".")
        if safe_direct:
            add(f"{safe_direct} item(ns) de cache/temporários seguros serão apagados direto, sem quarentena "
                "(são recriados automaticamente).")
    elif any(f.cleanable and f.clean_mode is not CleanMode.RECYCLE_BIN for f in findings):
        add("Quarentena desativada: todos os itens serão apagados definitivamente.")
    if manual:
        add(f"{len(manual)} item(ns) não serão apagados pelo app (protegidos ou limpeza manual): {lst(manual)}.")
    return msgs
