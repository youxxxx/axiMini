"""Fast extractor must be bit-identical to thrember's (the model was trained on the latter)."""

import random
import warnings
from pathlib import Path

import numpy as np
import pefile
import pytest
import thrember

from axi.features import FastPEFeatureExtractor, entropy_H, feature_names
from scripts.verify_features import synthetic

warnings.filterwarnings("ignore")
REF, FAST = thrember.PEFeatureExtractor(), FastPEFeatureExtractor()
SYS32 = Path(r"C:\Windows\System32")
REAL = [SYS32 / n for n in ("notepad.exe", "kernel32.dll", "cmd.exe", "ntdll.dll")]


def _same(bytez: bytes) -> None:
    r_ref, r_fast = REF.raw_features(bytez), FAST.raw_features(bytez)
    assert r_ref == r_fast
    assert REF.process_raw_features(r_ref).tobytes() == FAST.process_raw_features(r_fast).tobytes()


@pytest.mark.parametrize("name,bytez", synthetic(), ids=[n for n, _ in synthetic()])
def test_synthetic(name, bytez):
    _same(bytez)


@pytest.mark.parametrize("path", [p for p in REAL if p.exists()], ids=lambda p: p.name)
def test_real_pe(path):
    _same(path.read_bytes())


def test_entropy_matches_pefile():
    sec = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
    rnd = random.Random(0)
    for _ in range(200):
        data = bytes(min(255, int(rnd.expovariate(0.05))) for _ in range(rnd.randrange(1, 3000)))
        assert sec.entropy_H(data) == entropy_H(data)
    assert entropy_H(b"") == sec.entropy_H(b"") == 0.0


def test_feature_names_layout():
    names = feature_names()
    assert len(names) == thrember.PEFeatureExtractor().dim
    # thrember's categorical indices must land on the categorical fields
    cat = [names[i][1] for i in (2, 3, 4, 5, 6, 701, 702)]
    assert cat == ["general.is_pe"] + [f"general.start_byte[{i}]" for i in range(4)] \
        + ["header.coff.machine", "header.optional.subsystem"]
    assert np.unique([n for _, n in names]).size == len(names)
