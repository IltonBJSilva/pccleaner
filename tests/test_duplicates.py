from __future__ import annotations

from pccleaner.duplicate_finder import find_duplicates


def test_duplicates_by_hash(tmp_path):
    root = tmp_path / "d"
    (root / "s").mkdir(parents=True)
    data = b"A" * 200_000
    (root / "a.bin").write_bytes(data)
    (root / "s" / "b.bin").write_bytes(data)
    (root / "c.bin").write_bytes(b"A" * 199_999 + b"B")   # mesmo tamanho, conteúdo diferente
    (root / "small1").write_bytes(b"z" * 10)
    (root / "small2").write_bytes(b"z" * 10)
    groups = find_duplicates([str(root)], min_size_bytes=1024)
    assert len(groups) == 1
    g = groups[0]
    assert g.size_bytes == 200_000 and g.wasted_bytes == 200_000
    assert sorted(p.lower() for p in g.paths) == sorted(str(p).lower() for p in (root / "a.bin", root / "s" / "b.bin"))
    assert (root / "a.bin").exists() and (root / "s" / "b.bin").exists()   # nunca apaga
