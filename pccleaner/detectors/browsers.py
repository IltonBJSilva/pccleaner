"""Caches de navegadores. NUNCA cookies, senhas, histórico, sessões ou favoritos."""
from __future__ import annotations

from pccleaner.core.models import Category as Cat, Rule

from ._base import CONTENTS, S, rule

# (id, nome, raízes do "User Data"/perfil, perfis ficam em subpastas?)
CHROMIUM_BROWSERS: list[tuple[str, str, list[str], bool]] = [
    ("chrome", "Google Chrome", [r"%LOCALAPPDATA%\Google\Chrome\User Data"], True),
    ("chrome_beta", "Google Chrome Beta", [r"%LOCALAPPDATA%\Google\Chrome Beta\User Data"], True),
    ("chromium", "Chromium", [r"%LOCALAPPDATA%\Chromium\User Data"], True),
    ("edge", "Microsoft Edge", [r"%LOCALAPPDATA%\Microsoft\Edge\User Data"], True),
    ("brave", "Brave", [r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data"], True),
    ("vivaldi", "Vivaldi", [r"%LOCALAPPDATA%\Vivaldi\User Data"], True),
    # Opera guarda o perfil direto em "Opera Stable" (sem subpasta de perfil); o cache HTTP fica no LOCALAPPDATA.
    ("opera", "Opera", [r"%APPDATA%\Opera Software\Opera Stable",
                        r"%LOCALAPPDATA%\Opera Software\Opera Stable"], False),
    ("opera_gx", "Opera GX", [r"%APPDATA%\Opera Software\Opera GX Stable",
                              r"%LOCALAPPDATA%\Opera Software\Opera GX Stable"], False),
]

# Subpastas de cache por perfil (todas regeneráveis).
PROFILE_CACHES: list[tuple[str, str]] = [
    ("cache", "Cache"),
    ("code_cache", "Code Cache"),
    ("gpu_cache", "GPUCache"),
    ("sw_cache", r"Service Worker\CacheStorage"),
    ("sw_script_cache", r"Service Worker\ScriptCache"),
    ("dawn_cache", "DawnCache"),
    ("dawn_graphite", "DawnGraphiteCache"),
    ("dawn_webgpu", "DawnWebGPUCache"),
    ("media_cache", "Media Cache"),
    ("shader_cache_profile", "ShaderCache"),
]
# Caches na raiz do User Data (compartilhados entre perfis).
ROOT_CACHES: list[tuple[str, str]] = [
    ("shader_cache", "ShaderCache"),
    ("gr_shader_cache", "GrShaderCache"),
    ("graphite_dawn", "GraphiteDawnCache"),
]

LABELS = {
    "cache": "Cache", "code_cache": "Cache de código", "gpu_cache": "Cache de GPU",
    "sw_cache": "Cache de Service Workers", "sw_script_cache": "Scripts de Service Workers",
    "dawn_cache": "Cache WebGPU (Dawn)", "dawn_graphite": "Cache Graphite", "dawn_webgpu": "Cache WebGPU",
    "media_cache": "Cache de mídia", "shader_cache": "Cache de shaders", "shader_cache_profile": "Cache de shaders",
    "gr_shader_cache": "Cache de shaders (Skia)", "graphite_dawn": "Cache Graphite",
}

REASON = ("Arquivos de cache do navegador (páginas, scripts e imagens). Cookies, senhas, histórico e "
          "sessões NÃO são tocados.")
REC = ("Seguro. Feche o navegador antes para liberar arquivos em uso. Páginas podem carregar um pouco "
       "mais devagar na primeira visita.")


def rules() -> list[Rule]:
    out: list[Rule] = []
    for bid, bname, roots, has_profiles in CHROMIUM_BROWSERS:
        for key, sub in PROFILE_CACHES:
            if key == "shader_cache_profile" and has_profiles:
                # ShaderCache por perfil quase não existe; evita casar User Data\ShaderCache via glob.
                continue
            if has_profiles:
                paths = [rf"{r}\*\{sub}" for r in roots]
            else:
                paths = [rf"{r}\{sub}" for r in roots]
            out.append(rule(f"browser.{bid}.{key}", f"{bname} — {LABELS[key]}", Cat.BROWSER_CACHE, bname, S,
                            REASON, REC, CONTENTS, paths))
        if has_profiles:
            for key, sub in ROOT_CACHES:
                out.append(rule(f"browser.{bid}.{key}", f"{bname} — {LABELS[key]}", Cat.GPU_CACHE, bname, S,
                                "Cache de shaders/GPU do navegador, recriado automaticamente.", REC, CONTENTS,
                                [rf"{r}\{sub}" for r in roots]))

    ff = "Mozilla Firefox"
    out += [
        rule("browser.firefox.cache2", f"{ff} — Cache", Cat.BROWSER_CACHE, ff, S, REASON, REC, CONTENTS,
             [r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\cache2"]),
        rule("browser.firefox.startup_cache", f"{ff} — Cache de inicialização", Cat.BROWSER_CACHE, ff, S,
             REASON, REC, CONTENTS, [r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\startupCache"]),
        rule("browser.firefox.thumbnails", f"{ff} — Miniaturas", Cat.BROWSER_CACHE, ff, S, REASON, REC,
             CONTENTS, [r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\thumbnails"]),
        rule("browser.firefox.jumplist", f"{ff} — Cache da lista de atalhos", Cat.BROWSER_CACHE, ff, S,
             REASON, REC, CONTENTS, [r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\jumpListCache"]),
    ]
    return out
