from __future__ import annotations

import pytest

from pccleaner.quarantine import QuarantineError, QuarantineManager


@pytest.fixture
def qm(tmp_path):
    return QuarantineManager(tmp_path / "q")


def test_store_restore_roundtrip(tmp_path, qm):
    d = tmp_path / "w" / "app" / "logs"
    d.mkdir(parents=True)
    (d / "a.log").write_bytes(b"a" * 10)
    f = tmp_path / "w" / "app" / "single.txt"
    f.write_bytes(b"s" * 5)
    b = qm.new_batch()
    qm.store(b, str(d))
    qm.store(b, str(f))
    assert not d.exists() and not f.exists()
    (batch,) = qm.list_batches()
    assert batch.item_count == 2 and batch.size_bytes == 15
    assert qm.restore(b) == 2
    assert (d / "a.log").read_bytes() == b"a" * 10 and f.read_bytes() == b"s" * 5
    assert qm.list_batches() == []


def test_restore_never_overwrites(tmp_path, qm):
    f = tmp_path / "w" / "app" / "notes.txt"
    f.parent.mkdir(parents=True)
    f.write_text("original")
    b = qm.new_batch()
    qm.store(b, str(f))
    f.write_text("novo")
    assert qm.restore(b) == 1
    assert f.read_text() == "novo"
    assert (f.parent / "notes (restaurado).txt").read_text() == "original"


def test_purge_and_sizes(tmp_path, qm):
    f = tmp_path / "w" / "app" / "big.bin"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"x" * 1000)
    b = qm.new_batch()
    qm.store(b, str(f))
    assert qm.total_size() >= 1000
    assert qm.purge_expired(keep_days=7) == 0
    assert qm.purge(b) >= 1000
    assert qm.list_batches() == []


def test_invalid_batch_id(qm):
    with pytest.raises(QuarantineError):
        qm.restore("..\\..\\x")

