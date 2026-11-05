"""Faster, output-identical drop-ins for the slow parts of thrember's feature extractor.

The model was trained on features produced by thrember's original code, so every speedup here
must produce the *same bits*, not just "close" values. `scripts/verify_features.py` checks
this against the original on real files (log 12).

Hot spots (scripts/profile_features.py, 300 System32 files, mean share of extraction time):
    strings 56%   pefile parse 26%   general 7%   section 7%   byteentropy 3%
pefile parsing is deliberately left alone: its warnings are features, and a partial parse
would change them on exactly the malformed files that matter (log 12 §4).
"""

import math
from collections import OrderedDict

import numpy as np
import thrember
from thrember.features import GeneralFileInfo, SectionInfo, StringExtractor


# ---------------------------------------------------------------- entropy
def _first_occurrence_order(a: np.ndarray, n_present: int, chunk: int = 1 << 16) -> list[int]:
    """Distinct byte values of `a` in order of first occurrence.

    That's the iteration order of Counter(bytearray(data)) (dicts keep insertion order).
    It matters because float addition isn't associative: summing the same terms in another
    order can change the last bits of the entropy. Most byte values show up early, so we scan
    prefix chunks until all `n_present` values have been seen: usually 1 chunk, O(n) worst case.
    """
    seen: dict[int, int] = {}
    for off in range(0, len(a), chunk):
        vals, idx = np.unique(a[off:off + chunk], return_index=True)
        for v, i in zip(vals.tolist(), idx.tolist()):
            if v not in seen:
                seen[v] = off + i
        if len(seen) == n_present:
            break
    return sorted(seen, key=seen.__getitem__)


def entropy_H(data) -> float:
    """Bit-identical to pefile's `entropy_H` and thrember's inline copies of it.

    Original: Counter(bytearray(data)), i.e. a hash-map update per byte (~30 ns each).
    Here: np.bincount (a vectorized O(n) pass), then the same ≤ 256 float operations in the
    same order.
    """
    if not data:
        return 0.0
    a = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(a, minlength=256)
    order = _first_occurrence_order(a, int(np.count_nonzero(counts)))
    n = len(data)
    entropy = 0
    for v in order:
        p_x = float(int(counts[v])) / n
        entropy -= p_x * math.log(p_x, 2)
    return entropy


# ---------------------------------------------------------------- feature groups
class FastGeneralFileInfo(GeneralFileInfo):
    def raw_features(self, bytez, pe=None):
        size = len(bytez)
        return {
            "size": size,
            "entropy": entropy_H(bytez),
            "is_pe": 0 if pe is None else 1,
            "start_bytes": [
                int(bytez[0]),
                int(bytez[1]) if size >= 2 else 0,
                int(bytez[2]) if size >= 3 else 0,
                int(bytez[3]) if size >= 4 else 0,
            ],
        }


class FastSectionInfo(SectionInfo):
    def raw_features(self, bytez, pe):
        if pe is not None:
            # Shadow the method on these section *instances* only (no global monkeypatch):
            # upstream calls section.get_entropy() -> self.entropy_H(self.get_data()).
            for s in pe.sections:
                s.entropy_H = entropy_H
        return super().raw_features(bytez, pe)


class FastStringExtractor(StringExtractor):
    """Same output as StringExtractor.raw_features, with O(R) regex scans instead of O(S·R).

    Original: for each of S strings, for each of R=76 regexes, re.search(r, s): S·R Python-level
    calls (~100k on a large DLL). Here: join the strings with "\\n" and run each regex once over
    the joined text with finditer, then map match positions back to string indices by binary
    search on the start offsets. count[k] = number of distinct strings with >= 1 match.

    Why this is exact:
      * "\\n" (0x0a) is never part of a string (strings are runs of 0x20..0x7f), and no pattern
        can match it (no DOTALL, no \\s, no negated classes), so a match never spans two strings.
      * \\b at a string edge sees a non-word neighbour either way (start-of-text vs "\\n").
      * Within one string, finditer's first match is the leftmost one, the same as re.search.
    """

    def raw_features(self, bytez, pe):
        allstrings = self._allstrings.findall(bytez)
        if allstrings:
            string_lengths = [len(s) for s in allstrings]
            avlength = sum(string_lengths) / len(string_lengths)
            joined = b"".join(allstrings)
            # Upstream builds a Python list of ints byte by byte; a uint8 view gives the same counts.
            c = np.bincount(np.frombuffer(joined, dtype=np.uint8) - 0x20, minlength=96)
            csum = c.sum()
            p = c.astype(np.float32) / csum
            wh = np.where(c)[0]
            H = np.sum(-p[wh] * np.log2(p[wh]))
        else:
            avlength = 0
            c = np.zeros((96,), dtype=np.float32)
            H = 0
            csum = 0

        string_counts = {}
        if allstrings:
            text = b"\n".join(allstrings).decode()
            starts = np.cumsum([0] + [n + 1 for n in string_lengths[:-1]])
            for k, r in self._regexes.items():
                pos = [m.start() for m in r.finditer(text)]
                if pos:
                    owners = np.searchsorted(starts, pos, side="right") - 1
                    string_counts[k] = int(np.unique(owners).size)
        string_counts = OrderedDict(sorted(string_counts.items()))

        return {
            "numstrings": len(allstrings),
            "avlength": avlength,
            "printabledist": c.tolist(),
            "printables": int(csum),
            "entropy": float(H),
            "string_counts": string_counts,
        }


_REPLACEMENTS = {
    GeneralFileInfo: FastGeneralFileInfo,
    SectionInfo: FastSectionInfo,
    StringExtractor: FastStringExtractor,
}


class FastPEFeatureExtractor(thrember.PEFeatureExtractor):
    """thrember.PEFeatureExtractor with the slow groups swapped for exact drop-ins."""

    def __init__(self):
        super().__init__()
        self.features = [_REPLACEMENTS[type(fe)]() if type(fe) in _REPLACEMENTS else fe
                         for fe in self.features]


# ---------------------------------------------------------------- feature names
GROUP_KO = {  # Korean labels for UI output (CLI / dashboard)
    "general": "일반 정보", "histogram": "바이트 분포", "byteentropy": "바이트-엔트로피 분포",
    "strings": "문자열", "header": "PE 헤더", "section": "섹션", "imports": "임포트",
    "exports": "익스포트", "datadirectories": "데이터 디렉터리", "richheader": "Rich 헤더",
    "authenticode": "디지털 서명", "pefilewarnings": "PE 파싱 경고",
}

_HEADER_SCALARS = [
    "coff.timestamp", "coff.number_of_sections", "coff.number_of_symbols",
    "coff.sizeof_optional_header", "coff.pointer_to_symbol_table", "coff.machine",
    "optional.subsystem", "optional.major_image_version", "optional.minor_image_version",
    "optional.major_linker_version", "optional.minor_linker_version",
    "optional.major_os_version", "optional.minor_os_version",
    "optional.major_subsystem_version", "optional.minor_subsystem_version",
    "optional.sizeof_code", "optional.sizeof_headers", "optional.sizeof_image",
    "optional.sizeof_initialized_data", "optional.sizeof_uninitialized_data",
    "optional.sizeof_stack_reserve", "optional.sizeof_stack_commit",
    "optional.sizeof_heap_reserve", "optional.sizeof_heap_commit",
    "optional.address_of_entrypoint", "optional.base_of_code", "optional.image_base",
    "optional.section_alignment", "optional.checksum", "optional.number_of_rvas_and_sizes",
]


def feature_names(ext: thrember.PEFeatureExtractor | None = None) -> list[tuple[str, str]]:
    """(group, name) for each of the 2568 vector dims, mirroring each process_raw_features.

    Hashed groups (imports, exports, section tables, rich header) get bucket names like
    "imports.func_hash[517]": feature hashing is one-way, so the bucket is all we can name.
    """
    ext = ext or thrember.PEFeatureExtractor()
    g = {fe.name: fe for fe in ext.features}
    out: list[tuple[str, str]] = []

    def add(group, names):
        out.extend((group, f"{group}.{n}") for n in names)

    add("general", ["size", "entropy", "is_pe"] + [f"start_byte[{i}]" for i in range(4)])
    add("histogram", [f"byte[0x{b:02x}]" for b in range(256)])
    add("byteentropy", [f"H{h}_byte{b:x}x" for h in range(16) for b in range(16)])
    regexes = sorted(g["strings"].regex_idxs, key=g["strings"].regex_idxs.get)
    add("strings", ["numstrings", "avlength", "printables"]
        + [f"char[{chr(c + 0x20)!r}]" for c in range(96)] + ["entropy"]
        + [f"count[{r}]" for r in regexes])
    h = g["header"]
    add("header", _HEADER_SCALARS + [f"coff.char[{c}]" for c in h._image_characteristics]
        + [f"optional.dll_char[{c}]" for c in h._dll_characteristics]
        + [f"dos.{m}" for m in h._dos_members])
    add("section", ["n_sections", "n_zero_size", "n_empty_name", "n_rx", "n_w",
                    "max_entropy", "min_entropy", "max_size_ratio", "min_size_ratio",
                    "max_vsize_ratio", "min_vsize_ratio"]
        + [f"size_hash[{i}]" for i in range(50)] + [f"vsize_hash[{i}]" for i in range(50)]
        + [f"entropy_hash[{i}]" for i in range(50)] + [f"props_hash[{i}]" for i in range(50)]
        + [f"entry_name_hash[{i}]" for i in range(10)]
        + ["overlay_size", "overlay_size_ratio", "overlay_entropy"])
    add("imports", ["n_functions", "n_libraries"] + [f"lib_hash[{i}]" for i in range(256)]
        + [f"func_hash[{i}]" for i in range(1024)])
    add("exports", ["count_field"] + [f"hash[{i}]" for i in range(128)])
    dd = g["datadirectories"]._name_order
    add("datadirectories", [f"{n}.{k}" for n in dd for k in ("size", "rva")]
        + ["has_relocs", "has_dynamic_relocs"])
    add("richheader", ["n_pairs"] + [f"hash[{i}]" for i in range(32)])
    add("authenticode", ["num_certs", "self_signed", "empty_program_name", "no_countersigner",
                         "parse_error", "chain_max_depth", "latest_signing_time",
                         "signing_time_diff"])
    w = g["pefilewarnings"].warning_ids
    add("pefilewarnings", [f"warn{w[k]}[{k[:40]}]" for k in sorted(w, key=w.get)] + ["n_warnings"])
    assert len(out) == ext.dim, (len(out), ext.dim)
    return out
