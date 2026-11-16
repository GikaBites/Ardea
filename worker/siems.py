"""SIEM connections: one entry per Elastic cluster Ardea collects alerts from.

Read from siems/siems.json (mounted at /app/siems; path in SIEMS_FILE). Without that file, a single SIEM
with id "default" is built from the old ELASTIC_* / KIBANA_BASE_URL settings, so existing installs keep
working unchanged. The SAME file is used by the fetcher (fetcher_api_key) and the worker
(worker_api_key); keep fetcher/siems.py and worker/siems.py identical.

    {"siems": [
      {"id": "hq", "name": "Head office", "url": "https://elastic-hq:9200",
       "fetcher_api_key": "...", "worker_api_key": "...",
       "kibana_url": "https://kibana-hq:5601", "ca_cert": "/app/siems/hq-ca.crt",
       "alerts_index": ".alerts-security.alerts-default", "events_indices": "logs-*",
       "enabled": true,
       "context": ["Backups run nightly as svc.backup from D:\\Scripts"],          # MSP: facts for this SIEM
       "notify": {"smtp_to": ["soc@customer.example"], "slack_webhook_url": "https://hooks.slack.com/..."},
       "report_to": ["it-manager@customer.example"]}                              # MSP: monthly report
    ]}

The id is stored with every alert: keep it stable (renaming it orphans that SIEM's alerts).
"""
import json
import os
import pathlib
import re
from dataclasses import dataclass, field

ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
DEFAULT_ALERTS_INDEX = ".alerts-security.alerts-default"


NOTIFY_KEYS = {"smtp_to", "slack_webhook_url", "teams_webhook_url", "webhook_url", "webhook_secret"}
EMAIL_RE = re.compile(r"^[^@\s,;<>]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")


class SiemConfigError(Exception):
    pass


def _emails(value, where: str) -> tuple[str, ...]:
    items = value if isinstance(value, (list, tuple)) else str(value or "").split(",")
    out = tuple(str(i).strip() for i in items if str(i).strip())
    bad = [e for e in out if not EMAIL_RE.match(e)]
    if bad:
        raise SiemConfigError(f"{where}: not an e-mail address: {bad[0][:60]}")
    return out


def _notify(value, sid: str) -> dict:
    if not value:
        return {}
    if not isinstance(value, dict) or set(value) - NOTIFY_KEYS:
        raise SiemConfigError(f"siems.json '{sid}': notify may only contain {sorted(NOTIFY_KEYS)}")
    out = {}
    if value.get("smtp_to"):
        out["smtp_to"] = _emails(value["smtp_to"], f"siems.json '{sid}' notify.smtp_to")
    for key in ("slack_webhook_url", "teams_webhook_url", "webhook_url"):
        url = str(value.get(key) or "").strip()
        if url:
            if not url.startswith(("https://", "http://")):
                raise SiemConfigError(f"siems.json '{sid}': notify.{key} must be an http(s) URL")
            out[key] = url
    if value.get("webhook_secret"):
        out["webhook_secret"] = str(value["webhook_secret"])
    return out


@dataclass(frozen=True)
class Siem:
    id: str
    name: str
    url: str
    fetcher_api_key: str = field(default="", repr=False)
    worker_api_key: str = field(default="", repr=False)
    kibana_url: str = ""
    ca_cert: str = ""
    alerts_index: str = DEFAULT_ALERTS_INDEX
    events_indices: tuple[str, ...] = ("logs-*",)
    context: tuple[str, ...] = ()                                   # MSP: environment facts for this SIEM
    notify: dict = field(default_factory=dict, repr=False, compare=False, hash=False)   # MSP: alert routing
    report_to: tuple[str, ...] = ()                                 # MSP: scheduled report recipients

    @property
    def verify(self):
        """requests' verify=: a CA bundle path, or True (system CAs). Never off."""
        return self.ca_cert or True


def _env(name, default=""):
    v = (os.getenv(name) or "").strip()
    return default if not v or v.startswith("#") else v      # '# comment' = unset (Compose .env quirk)


def _indices(value) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = str(value or "").split(",")
    return tuple(i.strip() for i in items if str(i).strip())


def _from_env() -> list[Siem]:
    url = _env("ELASTIC_URL").rstrip("/")
    if not url:
        return []
    return [Siem(id="default", name=_env("SIEM_NAME", "Elastic"), url=url,
                 fetcher_api_key=_env("ELASTIC_FETCHER_API_KEY"), worker_api_key=_env("ELASTIC_WORKER_API_KEY"),
                 kibana_url=_env("KIBANA_BASE_URL").rstrip("/"), ca_cert=_env("ELASTIC_CA_CERT"),
                 alerts_index=_env("ELASTIC_ALERTS_INDEX", DEFAULT_ALERTS_INDEX),
                 events_indices=_indices(_env("ELASTIC_EVENTS_INDICES", "logs-*")))]


def parse(data: dict) -> list[Siem]:
    if not isinstance(data, dict) or not isinstance(data.get("siems"), list):
        raise SiemConfigError('siems.json must look like {"siems": [ {...}, ... ]}')
    out, seen = [], set()
    for n, item in enumerate(data["siems"], 1):
        if not isinstance(item, dict):
            raise SiemConfigError(f"siems.json entry {n} is not an object")
        if item.get("enabled", True) is False:
            continue
        sid = str(item.get("id", "")).strip()
        if not ID_RE.match(sid):
            raise SiemConfigError(f"siems.json entry {n}: id must be 1-32 characters: a-z, 0-9, '_' or '-'")
        if sid in seen:
            raise SiemConfigError(f"siems.json: id '{sid}' is used twice")
        seen.add(sid)
        url = str(item.get("url", "")).strip().rstrip("/")
        if not url.startswith(("https://", "http://")):
            raise SiemConfigError(f"siems.json '{sid}': url must start with https://")
        events = _indices(item.get("events_indices", "logs-*"))
        if not events:
            raise SiemConfigError(f"siems.json '{sid}': events_indices is empty")
        out.append(Siem(
            id=sid, name=str(item.get("name") or sid).strip()[:60], url=url,
            fetcher_api_key=str(item.get("fetcher_api_key", "")).strip(),
            worker_api_key=str(item.get("worker_api_key", "")).strip(),
            kibana_url=str(item.get("kibana_url", "")).strip().rstrip("/"),
            ca_cert=str(item.get("ca_cert", "")).strip(),
            alerts_index=str(item.get("alerts_index") or DEFAULT_ALERTS_INDEX).strip(),
            events_indices=events,
            context=tuple(str(c).strip()[:300] for c in (item.get("context") or []) if str(c).strip())[:20],
            notify=_notify(item.get("notify"), sid),
            report_to=_emails(item.get("report_to") or [], f"siems.json '{sid}' report_to")))
    return out


def load(path: str | None = None) -> list[Siem]:
    """All enabled SIEMs, in file order. The first one owns alerts stored before multi-SIEM support."""
    p = pathlib.Path(path or _env("SIEMS_FILE", "/app/siems/siems.json"))
    if p.is_file():
        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError as exc:
            raise SiemConfigError(f"{p} is not valid JSON: {exc}") from None
        siems = parse(data)
        if not siems:
            raise SiemConfigError(f"{p} has no enabled SIEM")
        return siems
    return _from_env()
