"""Read-only Elasticsearch client, one connection per SIEM in siems/siems.json.

Defence in depth: each API key's role is read-only (see elastic/roles.json), AND this client
can only issue POST <allowed-index>/_search. There is no code path that can write, delete,
update an alert's status or call any other API.

An investigation runs inside `with elastic.use(siem_id):`, so every search (including the SIEM
tools the model calls) goes to the SIEM the alert came from and nowhere else. Outside such a
block the first configured SIEM is used.
"""
import contextvars
import logging
import time
from contextlib import contextmanager

import requests

import config
import siems as siem_config

log = logging.getLogger("elastic")


class SiemError(Exception):
    """Raised for SIEM problems; the message is safe to show to the model."""


_SIEMS = {s.id: s for s in siem_config.load()}
_DEFAULT = next(iter(_SIEMS), None)
_current: contextvars.ContextVar[str | None] = contextvars.ContextVar("siem", default=None)
_sessions: dict[str, requests.Session] = {}


def configured() -> dict:
    return _SIEMS


def default_id() -> str | None:
    """The first SIEM: owns alerts stored before multi-SIEM support (siem column NULL)."""
    return _DEFAULT


def get(siem_id: str | None = None):
    sid = siem_id or _current.get() or _DEFAULT
    siem = _SIEMS.get(sid) if sid else None
    if siem is None:
        raise SiemError(f"SIEM '{sid}' is not configured" if sid else "no SIEM is configured")
    return siem


@contextmanager
def use(siem_id: str | None):
    """Route every search in this block to one SIEM. Raises SiemError if it is not configured."""
    siem = get(siem_id)
    token = _current.set(siem.id)
    try:
        yield siem
    finally:
        _current.reset(token)


def current_id() -> str | None:
    return _current.get() or _DEFAULT


def alerts_index() -> str:
    return get().alerts_index


def events_index() -> str:
    return get().events_indices[0]


def _session(siem) -> requests.Session:
    s = _sessions.get(siem.id)
    if s is None:
        s = _sessions[siem.id] = requests.Session()
        s.headers.update({"Authorization": f"ApiKey {siem.worker_api_key}",
                          "Content-Type": "application/json"})
    return s


def search(index: str, body: dict, *, retries: int = 2) -> dict:
    siem = get()
    if index != siem.alerts_index and index not in siem.events_indices:
        raise SiemError(f"index '{index}' is not allowed")
    body = dict(body)
    body.setdefault("timeout", f"{config.SIEM_TIMEOUT}s")       # server-side timeout
    body.setdefault("track_total_hits", 10000)
    url = (f"{siem.url}/{index}/_search"
           "?ignore_unavailable=true&allow_no_indices=true&allow_partial_search_results=true")
    last = None
    for attempt in range(retries + 1):
        try:
            r = _session(siem).post(url, json=body, timeout=config.SIEM_TIMEOUT + 5, verify=siem.verify)
            if r.status_code in (429, 502, 503, 504):
                raise SiemError(f"SIEM busy (HTTP {r.status_code})")
            if r.status_code == 400:
                # bad query is our bug, not transient — don't retry, don't leak the body
                log.error("[%s] elastic 400: %s", siem.id, r.text[:500])
                raise SiemError("query rejected by SIEM (400)")
            if r.status_code in (401, 403):
                raise SiemError(f"SIEM permission denied (HTTP {r.status_code})")
            r.raise_for_status()
            data = r.json()
            if data.get("timed_out"):
                data["_partial"] = True
            return data
        except SiemError as exc:
            last = exc
            if "busy" not in str(exc):
                raise
        except (requests.ConnectionError, requests.Timeout) as exc:
            last = SiemError(f"SIEM unreachable ({type(exc).__name__})")
        if attempt < retries:
            time.sleep(2 ** attempt * 2)
    raise last


def fetch_alert(elastic_id: str) -> dict | None:
    data = search(alerts_index(), {"size": 1, "query": {"ids": {"values": [elastic_id]}}})
    hits = data.get("hits", {}).get("hits", [])
    return hits[0] if hits else None
