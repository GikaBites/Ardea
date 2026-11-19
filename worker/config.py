"""All tunables in one place. Each is read from .env first, then from the Settings page (appsettings.py),
then the default here. The worker reloads this module when the Settings page changes."""
import os
import appsettings


def env(name, default=""):
    """Read a setting. Docker Compose turns `KEY=   # comment` in .env into the value '# comment',
    so a value starting with '#' is treated as unset. Every setting goes through here."""
    return appsettings.env(name, default)


def _int(name, default):
    return int(env(name, str(default)) or default)


def _bool(name, default="false"):
    return env(name, default).lower() in ("1", "true", "yes")


def _list(name, default=""):
    return [x.strip().lower() for x in env(name, default).split(",") if x.strip()]


# --- LLM -------------------------------------------------------------------
LLM_URL = env("LLM_URL", "http://ollama:11434")
MODEL = env("LLM_MODEL", "qwen3:14b")            # qwen2.5:14b-instruct still works
LLM_TEMPERATURE = float(env("LLM_TEMPERATURE", "0.1"))
LLM_TOP_P = float(env("LLM_TOP_P", "0.9"))
NUM_CTX = _int("LLM_NUM_CTX", 24576)                    # prompt + answer must fit, see agent._fit_context
NUM_PREDICT = _int("LLM_NUM_PREDICT", 2048)             # room for the full JSON verdict
# Reasoning ("thinking"). Empty = don't send the option (models without thinking, e.g. qwen2.5 or
# qwen3-*-instruct-2507). "false" = off (hybrid qwen3 thinks by DEFAULT: very slow on CPU). "true" = on.
# gpt-oss takes "low" | "medium" | "high".
_think = env("LLM_THINK", "").lower()
LLM_THINK = {"true": True, "false": False}.get(_think, _think if _think in ("low", "medium", "high") else None)
LLM_TIMEOUT = _int("LLM_TIMEOUT_SECONDS", 900)
LLM_SEED = _int("LLM_SEED", 42)                         # fixed seed: same input -> same verdict (reproducible evals)
_ka = env("LLM_KEEP_ALIVE", "-1")                 # keep the model loaded (an 18 GB reload on CPU is slow)
LLM_KEEP_ALIVE = int(_ka) if _ka.lstrip("-").isdigit() else _ka   # Ollama: number (-1 = forever) or "24h"
LLM_UNAVAILABLE_BACKOFF = _int("LLM_UNAVAILABLE_BACKOFF_SECONDS", 30)
# CPU-only: llama.cpp threads. Unset = Ollama's default. On 2 sockets, benchmark 12 / 24 (physical cores).
LLM_NUM_THREAD = _int("LLM_NUM_THREAD", 0)
PROMPT_VERSION = "2026.11"

# --- Agent budgets -----------------------------------------------------------
MAX_STEPS = _int("AGENT_MAX_STEPS", 8)                  # LLM turns in the investigation phase
MAX_TOOL_CALLS = _int("AGENT_MAX_TOOL_CALLS", 10)
MAX_WEB_SEARCHES = _int("AGENT_MAX_WEB_SEARCHES", 3)
MAX_WALL_SECONDS = _int("AGENT_MAX_WALL_SECONDS", 1200)
MAX_DUPLICATE_CALLS = 2
TOOL_RESULT_MAX_CHARS = _int("TOOL_RESULT_MAX_CHARS", 3500)
FINAL_SCHEMA_RETRIES = 2

# --- Verdict policy (deterministic guardrails applied AFTER the model) -------
MIN_CONFIDENCE_TO_CLOSE = _int("MIN_CONFIDENCE_TO_CLOSE", 70)   # FP/BP below this -> human review
# Second, adversarial model pass before any FP/BP closure (short output: ~10-20 s on CPU).
VERIFY_CLOSURES = _bool("VERIFY_CLOSURES", "true")
# Prior analyst feedback on similar alerts shown to the model (0 disables).
FEEDBACK_EXAMPLES = _int("FEEDBACK_EXAMPLES", 3)
FEEDBACK_LOOKBACK_DAYS = _int("FEEDBACK_LOOKBACK_DAYS", 180)

# --- Elastic ---------------------------------------------------------------------
# Connections (URL, read-only key, CA, indices) are per SIEM: see siems.py / siems/siems.json.
SIEM_TIMEOUT = _int("SIEM_TIMEOUT_SECONDS", 20)
SIEM_MAX_WINDOW_HOURS = _int("SIEM_MAX_WINDOW_HOURS", 72)        # raw-event searches
SIEM_MAX_BASELINE_DAYS = _int("SIEM_MAX_BASELINE_DAYS", 30)      # aggregations only
SIEM_MAX_ROWS = _int("SIEM_MAX_ROWS", 25)

# --- Web search ----------------------------------------------------------------
WEB_SEARCH_PROVIDER = env("WEB_SEARCH_PROVIDER", "disabled")  # brave | searxng | google_cse | disabled
WEB_SEARCH_PER_HOUR = _int("WEB_SEARCH_PER_HOUR", 60)
WEB_SEARCH_PER_DAY = _int("WEB_SEARCH_PER_DAY", 500)
# Log the sanitised query to outbound_requests but never send it. Use this for a week before going live.
WEB_SEARCH_DRY_RUN = _bool("WEB_SEARCH_DRY_RUN", "false")
# Query kinds the model may use. The free-text kinds (command_pattern, error_text) are the leakiest:
# enable them only after reviewing the dry-run log.
WEB_SEARCH_KINDS = _list("WEB_SEARCH_KINDS", "ip,domain,hash,cve,mitre,filename")
EGRESS_PROXY = env("EGRESS_PROXY", "")            # e.g. http://egress-proxy:3128
# Anything that identifies YOUR environment. Matched case-insensitively as substrings.
INTERNAL_DOMAINS = _list("INTERNAL_DOMAINS", "local,lan,corp,internal,intra")
SENSITIVE_TERMS = _list("SENSITIVE_TERMS", "")          # customer names, project names, AD domain ...

# --- Cache TTLs (seconds) ----------------------------------------------------------
CACHE_TTL_SIEM = _int("CACHE_TTL_SIEM", 900)
CACHE_TTL_WEB = _int("CACHE_TTL_WEB", 86400)

# --- Worker ------------------------------------------------------------------------
POLL_SECONDS = _int("WORKER_POLL_SECONDS", 5)
# "all": investigate alerts and do everything else (one worker). "tasks": only settings tests and analysts'
# questions, so they never wait behind an investigation (the optional worker-tasks service).
WORKER_ROLE = "tasks" if os.environ.get("WORKER_ROLE", "all").strip().lower() == "tasks" else "all"
SERVICE = "worker-tasks" if WORKER_ROLE == "tasks" else "worker"
MAX_ATTEMPTS = _int("WORKER_MAX_ATTEMPTS", 3)
LEASE_MINUTES = _int("WORKER_LEASE_MINUTES", 40)

# --- Notifications (True Positive alerts) ---------------------------------------------
NOTIFY_CHANNELS = _list("NOTIFY_CHANNELS", "")          # smtp, ntfy  (empty = off)
NOTIFY_VERDICTS = [v.strip() for v in env("NOTIFY_VERDICTS", "True Positive").split(",") if v.strip()]
NOTIFY_MIN_SEVERITY = env("NOTIFY_MIN_SEVERITY", "Informational")
NOTIFY_DETAIL = env("NOTIFY_DETAIL", "full").lower()       # full | minimal (verdict + link only)
NOTIFY_MAX_ATTEMPTS = _int("NOTIFY_MAX_ATTEMPTS", 8)
ARDEA_PUBLIC_URL = env("ARDEA_PUBLIC_URL", "").rstrip("/")
