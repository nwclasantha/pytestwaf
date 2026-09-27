"""Cross-device compatible file moving.

This must be used across the codebase for compatibility with Docker volumes
(fixes Invalid cross-device link when using os.rename).
"""

from __future__ import annotations

import shutil
from pathlib import Path


def file_move(source_path: str | Path, dest_path: str | Path) -> None:
    """Move a file from source to destination, handling cross-device moves.

    Args:
        source_path: Path to the source file.
        dest_path: Path to the destination file.

    Raises:
        FileNotFoundError: If source does not exist.
        ValueError: If source and destination are the same file.
        OSError: If the move operation fails.
    """
    src = Path(source_path)
    dst = Path(dest_path)

    if not src.exists():
        msg = f"source file does not exist: {src}"
        raise FileNotFoundError(msg)

    if dst.exists() and src.samefile(dst):
        msg = f"files {src} and {dst} are the same"
        raise ValueError(msg)

    shutil.move(str(src), str(dst))
