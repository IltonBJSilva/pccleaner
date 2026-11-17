"""Exportação de relatórios (JSON, CSV, HTML autocontido em pt-BR)."""
from __future__ import annotations

import csv
import datetime as _dt
import html
import json
import os
from dataclasses import asdict

from pccleaner import config
from pccleaner.analyzer.analysis import summarize
from pccleaner.core.models import CleanReport, SafetyLevel, ScanResult, human_size

FORMATS = ("json", "csv", "html")


def _ts(t: float | None) -> str:
    return _dt.datetime.fromtimestamp(t).strftime("%d/%m/%Y %H:%M") if t else "—"


def export_report(result: ScanResult, path: str, fmt: str, clean_report: CleanReport | None = None) -> str:
    fmt = (fmt or "").lower().lstrip(".")
    if fmt not in FORMATS:
        raise ValueError(f"Formato não suportado: {fmt} (use json, csv ou html)")
    path = os.path.abspath(path)
    if not path.lower().endswith("." + fmt):
        path += "." + fmt
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if fmt == "json":
        _write_json(result, path, clean_report)
    elif fmt == "csv":
        _write_csv(result, path, clean_report)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_html(result, clean_report))
    return path


def _clean_dict(cr: CleanReport) -> dict:
    return {"started_at": cr.started_at, "finished_at": cr.finished_at, "cancelled": cr.cancelled,
            "freed_bytes": cr.freed_bytes, "files_removed": cr.files_removed, "error_count": cr.error_count,
            "items": [asdict(i) for i in cr.items]}


def _write_json(result: ScanResult, path: str, cr: CleanReport | None) -> None:
    s = summarize(result)
    data = {
        "app": config.APP_NAME, "version": config.APP_VERSION,
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "scan": {"scan_id": result.scan_id, "started_at": result.started_at, "finished_at": result.finished_at,
                 "files_scanned": result.files_scanned, "bytes_scanned": result.bytes_scanned,
                 "recoverable_bytes": result.recoverable_bytes, "cancelled": result.cancelled,
                 "errors": result.errors},
        "summary": {"by_category": s["by_category"], "by_app": s["by_app"], "by_safety": s["by_safety"],
                    "recent_growth": [asdict(x) for x in s["recent_growth"]],
                    "old_large_files": [asdict(x) for x in s["old_large_files"]]},
        "findings": [f.to_dict() for f in result.findings],
        "top_folders": [asdict(x) for x in result.top_folders],
        "large_files": [asdict(x) for x in result.large_files],
        "clean": _clean_dict(cr) if cr else None,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


CSV_COLUMNS = ["nome", "categoria", "aplicativo", "seguranca", "caminho", "tamanho_bytes", "tamanho",
               "arquivos", "ultima_modificacao", "modo_limpeza", "motivo", "recomendacao"]


def _write_csv(result: ScanResult, path: str, cr: CleanReport | None) -> None:
    """';' + UTF-8 com BOM: abre corretamente no Excel pt-BR."""
    by_id = {i.finding_id: i for i in cr.items} if cr else {}
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(CSV_COLUMNS + (["liberado_bytes", "erros"] if cr else []))
        for f in sorted(result.findings, key=lambda x: x.size_bytes, reverse=True):
            row = [f.name, f.category.value, f.app, f.safety.label, f.path, f.size_bytes, human_size(f.size_bytes),
                   f.file_count, _ts(f.last_modified), f.clean_mode.value, f.reason, f.recommendation]
            if cr:
                it = by_id.get(f.id)
                row += [it.freed_bytes if it else "", " | ".join(it.errors) if it else ""]
            w.writerow(row)


_SAFETY_COLORS = {"seguro": ("#1f9d55", "#e3f6ea"), "revisar": ("#b7791f", "#fdf3dc"),
                  "atencao": ("#c05621", "#fde8dc"), "protegido": ("#6b7280", "#eceef1")}

_CSS = """:root{--bg:#f5f7fb;--card:#fff;--ink:#1d2433;--muted:#667085;--line:#e4e7ec;--accent:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#0f141c;--card:#171e29;--ink:#e6e9ef;--muted:#98a2b3;--line:#273142;--accent:#60a5fa}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 16px 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 12px}
.sub{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-top:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.card .k{color:var(--muted);font-size:12px;text-transform:uppercase}.card .v{font-size:24px;font-weight:600}
.card.accent .v{color:var(--accent)}.tbl{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line)}
.tbl th,.tbl td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
.tbl th{font-size:12px;color:var(--muted);text-transform:uppercase}.num{text-align:right!important;white-space:nowrap}
.path{font-family:Consolas,monospace;font-size:12px;word-break:break-all;color:var(--muted)}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600}
.bar{height:8px;border-radius:4px;background:var(--accent);min-width:2px}.scroll{overflow-x:auto}
footer{margin-top:40px;color:var(--muted);font-size:12px}"""


def _e(s: object) -> str:
    return html.escape(str(s), quote=True)


def _badge(level: str) -> str:
    fg, bg = _SAFETY_COLORS.get(level, ("#334155", "#e2e8f0"))
    label = SafetyLevel(level).label if level in SafetyLevel._value2member_map_ else level
    return f'<span class="badge" style="color:{fg};background:{bg}">{_e(label)}</span>'


def _card(k: str, v: str, accent: bool = False) -> str:
    return f'<div class="card{" accent" if accent else ""}"><div class="k">{_e(k)}</div><div class="v">{_e(v)}</div></div>'


def _n(x: int) -> str:
    return f"{x:,}".replace(",", ".")


def render_html(result: ScanResult, cr: CleanReport | None = None) -> str:
    s = summarize(result)
    p: list[str] = []
    a = p.append
    a(f"<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'><meta name='viewport' "
      f"content='width=device-width,initial-scale=1'><title>Relatório {_e(config.APP_NAME)}</title>"
      f"<style>{_CSS}</style></head><body><div class='wrap'>")
    a(f"<h1>Relatório de limpeza de disco</h1><div class='sub'>{_e(config.APP_NAME)} {_e(config.APP_VERSION)} · "
      f"varredura de {_e(_ts(result.started_at))} · duração {max(0.0, result.finished_at - result.started_at):.0f}s"
      f"{' · <b>cancelada</b>' if result.cancelled else ''}</div><div class='cards'>")
    a(_card("Recuperável (seguro + revisar)", human_size(result.recoverable_bytes), True))
    a(_card("Itens encontrados", str(len(result.findings))))
    a(_card("Arquivos analisados", _n(result.files_scanned)))
    a(_card("Dados analisados", human_size(result.bytes_scanned)))
    if cr:
        a(_card("Liberado na limpeza", human_size(cr.freed_bytes), True))
        a(_card("Arquivos removidos", _n(cr.files_removed)))
        a(_card("Erros/ignorados", str(cr.error_count)))
    a("</div><h2>Por nível de segurança</h2><table class='tbl'><tr><th>Nível</th><th class='num'>Tamanho</th></tr>")
    for lvl, b in s["by_safety"].items():
        a(f"<tr><td>{_badge(lvl)}</td><td class='num'>{_e(human_size(b))}</td></tr>")
    a("</table>")
    maxc = max(s["by_category"].values(), default=0) or 1
    a("<h2>Por categoria</h2><table class='tbl'><tr><th>Categoria</th><th style='width:40%'></th>"
      "<th class='num'>Tamanho</th></tr>")
    for name, b in s["by_category"].items():
        a(f"<tr><td>{_e(name)}</td><td><div class='bar' style='width:{b / maxc * 100:.1f}%'></div></td>"
          f"<td class='num'>{_e(human_size(b))}</td></tr>")
    a("</table><h2>Itens encontrados</h2><div class='scroll'><table class='tbl'><tr><th>Item</th><th>Categoria</th>"
      "<th>Segurança</th><th class='num'>Tamanho</th><th class='num'>Arquivos</th><th>Modificado</th></tr>")
    for f in sorted(result.findings, key=lambda x: x.size_bytes, reverse=True):
        a(f"<tr><td><b>{_e(f.name)}</b> <span class='sub'>· {_e(f.app)}</span><div class='path'>{_e(f.path)}</div>"
          f"<div class='sub'>{_e(f.reason)}</div></td><td>{_e(f.category.value)}</td><td>{_badge(f.safety.value)}</td>"
          f"<td class='num'>{_e(human_size(f.size_bytes))}</td><td class='num'>{f.file_count}</td>"
          f"<td>{_e(_ts(f.last_modified))}</td></tr>")
    if not result.findings:
        a("<tr><td colspan='6' class='sub'>Nenhum item encontrado.</td></tr>")
    a("</table></div>")
    if result.top_folders:
        a("<h2>Maiores pastas</h2><div class='scroll'><table class='tbl'><tr><th>Pasta</th><th class='num'>Tamanho</th>"
          "<th class='num'>Arquivos</th><th>Última alteração</th></tr>")
        for fs in result.top_folders[:50]:
            a(f"<tr><td class='path'>{_e(fs.path)}</td><td class='num'>{_e(human_size(fs.size_bytes))}</td>"
              f"<td class='num'>{fs.file_count}</td><td>{_e(_ts(fs.newest_mtime))}</td></tr>")
        a("</table></div>")
    if result.large_files:
        a("<h2>Arquivos grandes</h2><div class='scroll'><table class='tbl'><tr><th>Arquivo</th>"
          "<th class='num'>Tamanho</th><th>Modificado</th></tr>")
        for lf in sorted(result.large_files, key=lambda x: x.size_bytes, reverse=True)[:100]:
            a(f"<tr><td class='path'>{_e(lf.path)}</td><td class='num'>{_e(human_size(lf.size_bytes))}</td>"
              f"<td>{_e(_ts(lf.mtime))}</td></tr>")
        a("</table></div>")
    if cr:
        a(f"<h2>Resultado da limpeza{' (cancelada)' if cr.cancelled else ''}</h2><div class='scroll'><table class='tbl'>"
          "<tr><th>Caminho</th><th class='num'>Liberado</th><th class='num'>Removidos</th><th class='num'>Ignorados</th>"
          "<th>Quarentena</th><th>Observações</th></tr>")
        for it in cr.items:
            a(f"<tr><td class='path'>{_e(it.path)}</td><td class='num'>{_e(human_size(it.freed_bytes))}</td>"
              f"<td class='num'>{it.files_removed}</td><td class='num'>{it.files_skipped}</td>"
              f"<td>{'Sim' if it.quarantined else 'Não'}</td><td class='sub'>"
              f"{'<br>'.join(_e(x) for x in it.errors[:10])}</td></tr>")
        a("</table></div>")
    if result.errors:
        a(f"<h2>Avisos da varredura ({len(result.errors)})</h2><ul class='sub'>")
        a("".join(f"<li>{_e(x)}</li>" for x in result.errors[:200]))
        a("</ul>")
    a(f"<footer>Gerado em {_e(_dt.datetime.now().strftime('%d/%m/%Y %H:%M'))} por {_e(config.APP_NAME)}. "
      "Itens 'Seguro' são caches/temporários regeneráveis; revise os demais antes de apagar.</footer></div></body></html>")
    return "".join(p)
