"""Shared JSON file I/O — was defined independently in tool_selector and evidence_aggregator
(review-1 3.2); every pipeline artifact is a JSON object, so the dict check applies everywhere."""

import json
import os
from typing import Any


def load_json(path: str) -> dict[str, Any]:
    """Load a JSON object from disk."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def write_json(path: str, data: dict[str, Any]) -> None:
    """Write a JSON object to disk, creating the parent directory if needed."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
