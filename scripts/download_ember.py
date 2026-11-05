"""Download and extract one EMBER2024 subset (default: Win32_test) into data/ember2024/.

Run:  .venv/Scripts/python.exe scripts/download_ember.py [--file-type Win32] [--split test]

Uses huggingface_hub directly instead of thrember.download_dataset(), which calls os.chdir()
and always downloads/extracts/deletes in one go. Here the zip is cached and re-runs are no-ops.
"""

import argparse
import sys
import zipfile
from pathlib import Path

from huggingface_hub import hf_hub_download

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from axi import config  # noqa: E402

REPO_ID = "joyce8/EMBER2024"


def safe_extract(zip_path: Path, dest: Path) -> list[Path]:
    """Extract only .jsonl members, refusing any path that escapes `dest` (zip-slip)."""
    dest = dest.resolve()
    out = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.endswith(".jsonl"):
                continue
            target = (dest / info.filename).resolve()
            if not target.is_relative_to(dest):
                raise ValueError(f"unsafe path in zip: {info.filename!r}")
            if target.exists() and target.stat().st_size == info.file_size:
                out.append(target)  # already extracted
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                while chunk := src.read(1 << 20):
                    dst.write(chunk)
            out.append(target)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file-type", default=config.EMBER_FILE_TYPE)
    ap.add_argument("--split", default=config.EMBER_SPLIT)
    args = ap.parse_args()

    name = f"{args.file_type}_{args.split}.zip"
    zip_dir = config.DATA_DIR / "zips"
    zip_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] downloading {REPO_ID}/{name} -> {zip_dir}")
    zip_path = Path(hf_hub_download(repo_id=REPO_ID, filename=name, repo_type="dataset",
                                    local_dir=zip_dir))
    print(f"[+] zip ready: {zip_path} ({zip_path.stat().st_size / 1024**3:.2f} GiB)")

    files = safe_extract(zip_path, config.EMBER_DIR)
    total = sum(f.stat().st_size for f in files)
    print(f"[+] extracted {len(files)} jsonl files ({total / 1024**3:.2f} GiB) -> {config.EMBER_DIR}")
    for f in sorted(files):
        print(f"    {f.name}  {f.stat().st_size / 1024**2:8.1f} MiB")


if __name__ == "__main__":
    main()
