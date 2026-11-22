"""The Kibana Dev Tools requests that create Ardea's two read-only API keys, shown on the Settings page so
nobody has to open elastic/roles.json. publisher/elastic_roles.json is an exact copy of it (a test checks)."""
import functools
import json
import pathlib

ROLES = pathlib.Path(__file__).with_name("elastic_roles.json")


def _dump(value, indent: int = 0) -> str:
    """JSON with lists of plain values on one line, so the request stays short enough to read."""
    pad = "  " * (indent + 1)
    if isinstance(value, dict):
        if not value:
            return "{}"
        items = [f"{pad}{json.dumps(k)}: {_dump(v, indent + 1)}" for k, v in value.items()]
        return "{\n" + ",\n".join(items) + "\n" + "  " * indent + "}"
    if isinstance(value, list) and any(isinstance(v, (dict, list)) for v in value):
        return "[\n" + ",\n".join(pad + _dump(v, indent + 1) for v in value) + "\n" + "  " * indent + "]"
    return json.dumps(value)


def _request(block: dict) -> str:
    body = {k: v for k, v in block.items() if not k.startswith("_")}
    return "POST /_security/api_key\n" + _dump(body)


@functools.cache
def requests() -> dict[str, str]:
    """fetcher, worker (paid licence: hides password and token fields) and worker_basic (free licence)."""
    roles = json.loads(ROLES.read_text())
    return {"fetcher": _request(roles["ardea_fetcher"]), "worker": _request(roles["ardea_worker"]),
            "worker_basic": _request(roles["ardea_worker_basic"])}
