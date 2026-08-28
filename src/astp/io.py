from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if not isinstance(data, dict):
        raise TypeError(f"Expected a YAML object in {path}")

    return data


def load_model[T: BaseModel](
    path: Path,
    model: type[T],
) -> T:
    return model.model_validate(load_yaml(path))


def dump_yaml(data: BaseModel | dict[str, Any], path: Path | None = None) -> str:
    payload = data.model_dump(mode="json") if isinstance(data, BaseModel) else data
    rendered = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    if path is not None:
        path.write_text(rendered, encoding="utf-8")
    return rendered
