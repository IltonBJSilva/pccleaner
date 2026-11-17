"""Regras casadas por nome de pasta durante a varredura profunda (projetos de desenvolvimento)."""
from __future__ import annotations

from pccleaner.core.models import Category as Cat, Rule

from ._base import C, RV, S, WHOLE, rule

BA = Cat.BUILD_ARTIFACTS
DC = Cat.DEV_CACHE

GEN_REC = "Seguro; a pasta é recriada automaticamente pela ferramenta quando necessário."


def rules() -> list[Rule]:
    return [
        rule("proj.pycache", "Cache de bytecode Python (__pycache__)", DC, "Python", S,
             "Bytecode .pyc compilado pelo Python; recriado automaticamente.", GEN_REC, WHOLE,
             dir_names=("__pycache__",)),
        rule("proj.pytest_cache", "Cache do pytest", DC, "pytest", S, "Cache do pytest (.pytest_cache).",
             GEN_REC, WHOLE, dir_names=(".pytest_cache",)),
        rule("proj.mypy_cache", "Cache do mypy", DC, "mypy", S, "Cache do verificador de tipos mypy.",
             GEN_REC, WHOLE, dir_names=(".mypy_cache",)),
        rule("proj.ruff_cache", "Cache do Ruff", DC, "Ruff", S, "Cache do linter Ruff.", GEN_REC, WHOLE,
             dir_names=(".ruff_cache",)),
        rule("proj.tox", "Ambientes do tox", DC, "tox", RV,
             "Ambientes virtuais criados pelo tox; recriados no próximo 'tox'.",
             "Revise: o próximo 'tox' reinstalará as dependências.", WHOLE, dir_names=(".tox",)),
        rule("proj.next_cache", "Cache do Next.js", DC, "Next.js", S, "Cache de build do Next.js (.next/cache).",
             GEN_REC, WHOLE, dir_names=("cache",), parent_names=(".next",)),
        rule("proj.angular_cache", "Cache do Angular", DC, "Angular", S, "Cache de build do Angular CLI.",
             GEN_REC, WHOLE, dir_names=("cache",), parent_names=(".angular",)),
        rule("proj.vite", "Cache do Vite", DC, "Vite", S, "Dependências pré-empacotadas do Vite (.vite).",
             GEN_REC, WHOLE, dir_names=(".vite",)),
        rule("proj.parcel", "Cache do Parcel", DC, "Parcel", S, "Cache do bundler Parcel.", GEN_REC, WHOLE,
             dir_names=(".parcel-cache",)),
        rule("proj.turbo", "Cache do Turborepo", DC, "Turborepo", S, "Cache local do Turborepo (.turbo).",
             GEN_REC, WHOLE, dir_names=(".turbo",)),
        rule("proj.node_modules", "Dependências Node.js (node_modules)", Cat.DEV_DEPENDENCIES, "Node.js", C,
             "Dependências instaladas de um projeto Node.js (há package.json ao lado).",
             "Atenção: o projeto deixa de funcionar até rodar 'npm install' (ou yarn/pnpm) de novo. "
             "Ideal para projetos parados. Nunca selecionado por padrão.", WHOLE,
             dir_names=("node_modules",), sibling_markers=("package.json",), command_hint="npm install"),
        rule("proj.rust_target", "Saída de build Rust (target)", BA, "Rust", RV,
             "Artefatos de compilação do Cargo (há Cargo.toml ao lado).",
             "Revise: o próximo 'cargo build' recompila tudo. Equivale a 'cargo clean'.", WHOLE,
             dir_names=("target",), sibling_markers=("Cargo.toml",), command_hint="cargo clean"),
        rule("proj.build_dist", "Saída de build (build/dist)", BA, "Projeto", RV,
             "Pasta de saída de build de um projeto (marcador de projeto encontrado ao lado).",
             "Revise: pode conter um build que você pretende distribuir. Recriado ao compilar de novo.", WHOLE,
             dir_names=("build", "dist"),
             sibling_markers=("package.json", "pyproject.toml", "setup.py", "setup.cfg", "CMakeLists.txt",
                              "build.gradle", "build.gradle.kts", "vite.config.ts", "vite.config.js",
                              "tsconfig.json")),
        rule("proj.gradle_project", "Cache Gradle do projeto (.gradle)", BA, "Gradle", RV,
             "Cache local do Gradle dentro do projeto.", "Revise: recriado no próximo build.", WHOLE,
             dir_names=(".gradle",),
             sibling_markers=("settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts",
                              "gradlew")),
        rule("proj.dotnet_bin_obj", "Saída de build .NET (bin/obj)", BA, ".NET", RV,
             "Pastas bin/obj de um projeto .NET (há arquivo de projeto ao lado).",
             "Revise: recriadas no próximo build. Equivale a 'dotnet clean' + apagar as pastas.", WHOLE,
             dir_names=("bin", "obj"), sibling_markers=("*.csproj", "*.fsproj", "*.vbproj", "*.vcxproj")),
        rule("proj.unity_library", "Unity — Library do projeto", BA, "Unity", RV,
             "Cache de importação de assets do Unity (Library). Recriado ao abrir o projeto.",
             "Revise: reabrir o projeto pode levar muito tempo para reimportar os assets.", WHOLE,
             dir_names=("Library",), sibling_markers=(r"ProjectSettings\ProjectVersion.txt",)),
        rule("proj.unreal_intermediate", "Unreal — Intermediate/DerivedDataCache do projeto", BA, "Unreal Engine",
             RV, "Arquivos intermediários e cache derivado de um projeto Unreal (há .uproject ao lado).",
             "Revise: o projeto precisará recompilar e reprocessar shaders.", WHOLE,
             dir_names=("Intermediate", "DerivedDataCache"), sibling_markers=("*.uproject",)),
        rule("proj.godot", "Godot — cache do projeto (.godot)", BA, "Godot", RV,
             "Cache de importação do Godot 4 (.godot). Recriado ao abrir o projeto.",
             "Revise: o Godot reimportará os assets ao abrir o projeto.", WHOLE,
             dir_names=(".godot",), sibling_markers=("project.godot",)),
    ]
