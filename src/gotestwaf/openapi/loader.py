"""OpenAPI specification loading and validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ruamel.yaml import YAML


def load_openapi_spec(location: str) -> dict[str, Any]:
    """Load an OpenAPI file, parse it and return as dict.

    Args:
        location: Path to the OpenAPI YAML/JSON file.

    Returns:
        Parsed OpenAPI specification as dictionary.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the file can't be parsed.
    """
    path = Path(location)
    if not path.exists():
        msg = f"couldn't load OpenAPI file: {location}"
        raise FileNotFoundError(msg)

    yaml = YAML()
    with path.open(encoding="utf-8") as f:
        doc = yaml.load(f)

    if doc is None:
        msg = f"empty OpenAPI spec: {location}"
        raise ValueError(msg)

    return dict(doc)
