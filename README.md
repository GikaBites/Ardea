# Ardea

**AI triage for Elastic Security that runs on your own hardware. No alert data leaves your network.**

Website: [ardeasecurity.com](https://ardeasecurity.com) · Support: support@ardeasecurity.com

Ardea pulls new Elastic Security detection alerts, has a local LLM (in Ollama) investigate each one with
read-only SIEM queries, and publishes a verdict with the evidence behind it in a web UI:

- **True Positive**: malicious or unauthorised activity, supported by evidence
- **Benign Positive**: the rule fired correctly on legitimate activity
- **False Positive**: the rule misfired
- **Needs Human Review**: evidence is missing or contradictory, or the impact is too high to close automatically

Every verdict cites the log events it is based on, and the full investigation trail is kept. Guardrails in
code, not in the prompt, decide what may be closed automatically: high-impact tactics such as credential
access, suspected prompt injection and thin evidence always go to a person.

![Ardea alert view: a true positive with findings, evidence references and recommended actions](img/screenshot.png)

## Try the demo (2 minutes, no SIEM needed)

```bash
git clone https://github.com/GikaBites/ardea.git && cd ardea
docker compose -f docker-compose.demo.yml up -d --build
```

Open https://localhost:8443, accept the browser warning (a certificate made on your computer) and sign in
as `demo` / `demo`. The demo holds about eight weeks of sample alerts and five example investigations (written by hand to show the UI), with all
paid features switched on. It needs no Elastic and no Ollama, and it is reachable only from your computer.
Remove it with `docker compose -f docker-compose.demo.yml down -v`.

## How it works

<img src="img/diagram.png" width="500" height="400">

[REVIEW.md](REVIEW.md) describes how Ardea works in detail.

---

## Editions

Ardea is free to use. The paid editions add convenience features; they never change how alerts are
triaged.

| | Community (free) | Pro | MSP |
|---|:---:|:---:|:---:|
| LLM investigation, all guardrails, closure review, prompt-injection defences | ✓ | ✓ | ✓ |
| Web UI with users, roles, audit trail and analyst feedback | ✓ | ✓ | ✓ |
| Web search with the outbound sanitiser | ✓ | ✓ | ✓ |
| Collect from one Elastic cluster | ✓ | ✓ | ✓ |
| [Incidents](#incidents): related alerts grouped into one incident with one timeline, followed across hosts | | ✓ | ✓ |
| [Queue and response deadlines](#queue-and-response-deadlines): assign alerts, deadlines per severity, overdue warnings | | ✓ | ✓ |
| [NIS2 report drafts and incident export](#nis2-report-drafts-and-incident-export): 24-hour, 72-hour and final report drafted from the evidence; ZIP or PDF of an incident | | ✓ | ✓ |
| [Silent-source alarm and handover digest](#monitoring-and-handover-digest): warning when a SIEM stops sending events; a daily summary of what needs a person | | ✓ | ✓ |
| [Reports and insights](#reports-and-insights): management report (print / PDF), weekly trends, scheduled report e-mails | | ✓ | ✓ |
| [Ask about this alert](#ask-about-this-alert): follow-up questions answered from the evidence, with new read-only queries and citations | | ✓ | ✓ |
| [Rule-tuning advisor](#rule-tuning-advisor): ready-to-paste Elastic exceptions for patterns that are always harmless | | ✓ | ✓ |
| [Suppressions](#suppressions): patterns your analysts keep closing are closed without an investigation, with a reason and an expiry | | ✓ | ✓ |
| [Integrations](#integrations): Slack, Microsoft Teams, webhook, Jira, TheHive, plus e-mail and ntfy | | ✓ | ✓ |
| [Playbook pack](#playbook-pack): ready-made playbooks for 30 noisy Elastic prebuilt rules, updated monthly | | ✓ | ✓ |
| [Single sign-on](#single-sign-on) through your identity provider | | ✓ | ✓ |
| "Investigate again" button, CSV export, eval-case export | | ✓ | ✓ |
| [Several Elastic clusters](#several-siems) with per-user SIEM access | | | ✓ |
| [Watched hosts](#monitoring-and-handover-digest): warning when a domain controller or server stops reporting | | | ✓ |
| [Per-customer setup](#per-customer-setup-msp): own alert routing, monthly reports, facts and playbooks per customer; settings templates applied to many customers at once | | | ✓ |
| Customer portal (read-only logins per customer), usage export for billing | | | ✓ |
| Run Ardea for your customers, [your own branding](#own-branding) | | | ✓ |

**Pro and MSP are on sale** at [ardeasecurity.com](https://ardeasecurity.com/#pricing). The Community edition
stays free and complete for one cluster. The [licence](LICENSE) does not allow changing, disabling or
bypassing the licence check.

**Safety is the same in every edition.** A missing, expired or unreachable licence never stops triage and
never weakens a guardrail: Ardea falls back to Community, keeps every per-user restriction, and alerts
already queued are still triaged. If the licence server cannot be reached, the paid features stay on for
30 days.

**Activating a licence.** As an admin, paste the key from your purchase e-mail under **Settings → Licence** and
click **Check the licence now**. (Or put it in `.env` as `ARDEA_LICENSE_KEY` and run `docker compose up -d worker`.) Check it with `docker compose exec worker python licensing.py`; admins also
see the edition on the **Users** page. The worker contacts the Ardea store's licence server (`api.polar.sh`) once a day with only the
key and an installation name, never alert data. With the egress lockdown, start the `egress` profile and set
`ARDEA_LICENSE_PROXY=http://egress-proxy:3128`. For a network without internet access, ask for an
offline licence file and put it in `license/ardea.license`.

---

## Requirements

| Component | Notes |
|---|---|
| Docker host | Linux with Docker Engine and Docker Compose v2. 2 CPU cores, 4 GB RAM and 10 GB of disk are enough for Ardea itself. |
| Elastic Security | Detection rules writing alerts to `.alerts-security.alerts-default`, and endpoint/Windows events in `logs-*` (Elastic Defend, or Sysmon via Elastic Agent). |
| Ollama | On the Docker host or another machine on the LAN, with a model that supports tool calling. |

**Choosing a model.** `qwen3:30b-a3b-instruct-2507-q4_K_M` is the recommended default. It is a mixture-of-experts
model with only 3B active parameters, so it runs acceptably even without a GPU: on 2× Xeon Gold 6126 it reads
about 85 tokens/s and writes about 9 tokens/s, which is roughly 3 minutes per alert. It needs about 20 GB of RAM
or VRAM. With a 12–16 GB GPU, `qwen3:14b` is faster. Avoid models below 8B parameters or below Q4 quantisation.

---

## Installation

### Quick install

On the Linux server that will run Ardea (Docker installed, and Ollama running there or on another machine):

```bash
curl -fsSL https://raw.githubusercontent.com/GikaBites/Ardea/main/install.sh | bash
```

It checks Docker, memory and disk, downloads Ardea into `./ardea`, asks four questions (the address people
type in the browser, where Ollama runs, the model, the time zone), writes `.env` with a random database
password, starts everything and prints the address and the first admin password. Then open **Settings → Start
here** and add your SIEM. Running it again keeps your `.env` and only updates and restarts Ardea. Without
questions: `ARDEA_ADDRESS=ardea.example.com LLM_URL=http://10.0.0.5:11434 LLM_MODEL=qwen3:14b ./install.sh --yes`.

The steps below do the same by hand, and explain the Elastic API keys and HTTPS in detail.

### 1. Install Ollama and pull the model

On the machine that will run the model:

```bash
curl -fsSL https://ollama.com/install.sh | sh
# Arch Linux: sudo pacman -S ollama   (or ollama-cuda / ollama-rocm for your GPU)
ollama pull qwen3:30b-a3b-instruct-2507-q4_K_M
```

If Ollama runs on a different machine from Ardea, make it listen on the network and keep the model loaded.
Run `sudo systemctl edit ollama` and add:

```ini
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
Environment="OLLAMA_KEEP_ALIVE=-1"
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
```

Restart it with `sudo systemctl restart ollama`, then check from the Ardea host:

```bash
curl http://<ollama-host>:11434/api/tags
```

Ollama has no authentication, so allow only the Ardea host to reach port 11434.

### 2. Create two read-only Elastic API keys

[`elastic/roles.json`](elastic/roles.json) defines two keys:

- **fetcher**: reads the alerts index only
- **worker**: reads alerts and `logs-*`, with password and token fields hidden

Neither key can write anything. In Kibana → **Dev Tools**, create each key using its block from the file as the
request body:

```
POST /_security/api_key
{
  "name": "ardea-fetcher",
  "expiration": "180d",
  "role_descriptors": { ... copy from elastic/roles.json ... }
}
```

Keep the `encoded` value from each response for the next step. The keys expire after 180 days, so set a reminder
to renew them.

### 3. Get the code and configure it

```bash
git clone https://github.com/GikaBites/ardea.git
cd ardea
cp .env.example .env
chmod 600 .env
```

In `.env` you only need **`POSTGRES_PASSWORD`** (a long random password) and the HTTPS address of step 4.
Everything else (the AI model, your SIEMs, notifications, the licence) can be set after the first sign-in on
the **Settings** page of the web UI (step 6).

If you prefer to keep everything in files, every setting is documented in [`.env.example`](.env.example) and
still works: a value in `.env` always wins and is shown read-only on the Settings page. The ones that matter most:

| Setting | Value |
|---|---|
| `LLM_URL` | `http://<ollama-host>:11434`, or `http://host.docker.internal:11434` if Ollama runs on the Docker host |
| `LLM_MODEL` | The model you pulled, exactly as `ollama list` shows it |
| `LLM_NUM_CTX` | `16384` without a GPU, `24576` with one |
| `ELASTIC_URL` | e.g. `https://elastic.example.com:9200` |
| `ELASTIC_FETCHER_API_KEY`, `ELASTIC_WORKER_API_KEY` | The two `encoded` values from step 2 |
| `ELASTIC_CA_CERT` | Only if Elasticsearch uses a private CA: the path to the CA file inside the containers |
| `KIBANA_BASE_URL` | e.g. `https://kibana.example.com`. The UI only links to this host. |
| `INTERNAL_DOMAINS` | Your internal DNS suffixes and AD domain |

Put comments in `.env` on their own line, never after a value: Docker Compose would read the comment as part of
the value.

With more than one Elastic cluster, add them on the Settings page, or leave the `ELASTIC_*` settings empty and use
`siems/siems.json` (see [Several SIEMs](#several-siems)).

### Several SIEMs

*MSP edition. Other editions collect only from the first SIEM in `siems.json`.*

Ardea can collect alerts from several Elastic clusters (for example one per site or per customer). Each alert is
investigated only in the cluster it came from, and the UI can show one SIEM or all of them.

1. Create the two read-only API keys of step 2 **in every cluster**.
2. Copy the example and fill in one entry per cluster:

   ```bash
   cp siems/siems.example.json siems/siems.json
   sudo chown 10001 siems/siems.json && sudo chmod 600 siems/siems.json   # the containers run as uid 10001
   ```

   | Field | Value |
   |---|---|
   | `id` | Short, stable id: lowercase letters, digits, `-`, `_`. It is stored with every alert, so don't rename it. |
   | `name` | Shown in the UI and in notifications |
   | `url` | Elasticsearch URL, e.g. `https://elastic-hq.example.com:9200` |
   | `fetcher_api_key`, `worker_api_key` | The two `encoded` keys of that cluster |
   | `kibana_url` | That cluster's Kibana. Links in the UI and notifications only go to this host. |
   | `ca_cert` | Optional. A private CA: put the file in `siems/` and write `/app/siems/<file>` |
   | `alerts_index`, `events_indices` | Optional. Defaults: `.alerts-security.alerts-default` and `logs-*` |
   | `enabled` | Optional. `false` stops collecting from that cluster |

3. `docker compose up -d --build`. The fetcher log lists the SIEMs it polls.

The Settings page does the same without a file (**Settings → SIEMs → Add a SIEM**). When `siems/siems.json`
exists, it wins: the SIEM list on the Settings page becomes read-only, and the `ELASTIC_*`, `KIBANA_BASE_URL` and
`SIEM_NAME` settings in `.env` are ignored.
Alerts collected before this file existed belong to the **first** SIEM in it, so put the cluster you used until now
first. `siems/siems.json` and certificates in `siems/` are git-ignored: they contain secrets.

Same host names in two SIEMs are treated as different machines: duplicates are only merged, and "same host" analyst
feedback is only reused, within one SIEM.

**Removing a SIEM.** *Settings → SIEMs → Change → Remove this SIEM* stops collecting from it; its alerts and
verdicts stay. Tick *Also delete everything stored for it* and type its ID to delete its alerts, verdicts,
investigation steps, feedback, queue history, questions, suppressions and health status as well. A SIEM that is
no longer configured (removed earlier, or taken out of `siems/siems.json`) and still has data is listed under
*Data from SIEMs that are no longer configured*, with a **Delete its data** button. Users limited to that SIEM keep
their other SIEMs. Deleting cannot be undone and is recorded in the change log. Alerts stored before multi-SIEM
support (no SIEM ID) are never deleted this way.

### 4. Set up HTTPS for the web UI

The UI is served over HTTPS by a Caddy container; plain HTTP on port 80 only redirects to HTTPS. In `.env`, list
every name and address users will type in the browser:

```ini
ARDEA_SITE_ADDRESS=ardea.example.com, 192.168.1.20
ARDEA_DEFAULT_SNI=192.168.1.20
```

`ARDEA_DEFAULT_SNI` is needed when users open Ardea by IP address: browsers do not send a host name for an
IP, so Caddy uses this entry to pick the certificate.

**Certificate.** By default (`ARDEA_TLS=internal`) Caddy creates its own certificate authority and a
certificate for those names. Browsers trust it once its root certificate is installed on the analysts' machines
(Windows: *Trusted Root Certification Authorities*, or deploy it by Group Policy). After the first start:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./ardea-root-ca.crt
```

To use a certificate from your own CA instead, put `ardea.crt` (with the chain) and `ardea.key` in
`caddy/certs/` and set `ARDEA_TLS=/certs/ardea.crt /certs/ardea.key`. With a certificate that browsers
already trust, you can also set `ARDEA_HSTS_SECONDS=31536000`.

If ports 80 or 443 are already used on the host, change `ARDEA_HTTP_BIND` / `ARDEA_HTTPS_BIND`.

### 5. Start Ardea and sign in

```bash
docker compose up -d
docker compose ps                      # all containers should become "healthy"
docker compose logs -f worker          # look for "worker ... running, model=..."
```

The database is created on the first start. The fetcher first picks up the alerts of the last 12 hours, then
polls every 3 minutes (`FETCH_INTERVAL_SECONDS`).

On its first start the UI creates the user **admin** with a random one-time password, written once to the
publisher's log:

```bash
docker compose logs publisher | grep -A1 "Temporary password"
```

Open `https://<host>/`, sign in as `admin` with that password, and choose your own password (at least 12
characters). Then open **Settings** (step 6) and create accounts for the other analysts under **Users** (see [Users and roles](#users-and-roles)).

### 6. Configure Ardea on the Settings page

Signed in as an admin, open **Settings**. It opens on **Start here**: a checklist of what is set up, what is
missing and what needs attention, with a button to each part. The menu on the left has the four parts every
installation needs, in order, then the optional ones. Each page says what it is for and whether you need it;
settings most people never change are under **Advanced settings**, closed by default, and fields only appear when
they apply (the SearXNG address only when you pick SearXNG, the mail server only when you switch on e-mail).
Changes apply within about 30 seconds, without a restart.

| Section | What you set there |
|---|---|
| 1 Licence | Your Pro or MSP licence key, or an offline licence file. Skip it for the free edition |
| 2 SIEMs (Elastic) | Each Elastic cluster in three steps: name, address, the two read-only API keys of step 2. MSP: per-customer facts, alert copies, reports and settings templates |
| 3 AI model | Where Ollama runs and the model name. **Test the connection** lists the installed models |
| 4 Alerts to your team | What to tell the team, and how: switch on e-mail, phone push (ntfy), Slack, Teams, webhook, Jira or TheHive, each with its own test button (Pro) |
| How alerts are handled | When Ardea may close an alert by itself, the double check, rules to ignore |
| Web search | Provider and key, internal domains and words that must never be searched |
| Playbook pack, Queue and deadlines, Monitoring and daily digest, Reports and branding, NIS2 details | The Pro and MSP extras |
| Change log | Who changed which setting and when. Values are never recorded |

How the Settings page keeps secrets safe:

- **Write-only.** A saved key or password is shown only as "Saved (ends in 7f3a)". Nobody can read it back,
  admins included.
- **The web UI cannot open them.** Secrets are encrypted with a key pair that the worker creates on its first
  start. Only the worker and fetcher hold the private half (Docker volume `settings_keys`); the web UI has only the
  public half. Someone who took over the web UI could still not read your Elastic keys or SMTP password.
- **Bound to their host.** An Elastic API key only opens for the cluster URL it was saved with, and the SMTP
  password only for its SMTP server. Changing the address clears the secret, so it can never be sent somewhere new
  without being typed in again.
- **Tests run in the worker.** The test buttons queue a check that the worker carries out with the saved values;
  results never contain the secret or a full URL. They can take a minute while the worker investigates an alert.
- **Your password again.** Saving a key, password, the licence or a SIEM opens a pop-up that asks for your own
  sign-in password (not with single sign-on). It is checked before anything is sent, so a typo never loses what you
  filled in. Wrong answers count towards the normal lockout. If a save fails for any reason, the form keeps what
  you typed (except keys and passwords, which are never sent back to the browser).

What stays in `.env`: database credentials, the HTTPS address and certificate, single sign-on, the egress proxy,
web UI session limits and demo mode. A value set in `.env` always wins and appears read-only on the Settings page;
remove it from `.env` to manage it there.

**Backups** include the `settings_keys` volume automatically (see [Backups and system health](#backups-and-system-health)).
Without that key, the worker creates a new one and the Settings page asks you to enter the saved keys and
passwords again (nothing else is lost).

### 7. Tune it for your environment

- **Playbooks**: [`worker/playbooks.yaml`](worker/playbooks.yaml) holds rule-specific guidance and the SIEM queries
  that run before the LLM starts. Write playbooks for your noisiest rules first. Changes are picked up
  automatically.
- **Environment facts**: the `context:` list at the end of `playbooks.yaml`, e.g. where backup scripts live, how
  service accounts are named, which subnet the vulnerability scanner uses. The model relies on these, so add only
  verified facts.
- **Ignored rules**: [`fetcher/ignored_rules.json`](fetcher/ignored_rules.json) lists rules that are never sent to
  triage (`ignored` = exact rule names, `match` = parts of names). Apply changes with
  `docker compose up -d --build fetcher`.

---

## Using Ardea

The **Alerts** page has three parts:

- **Verdict tiles** with live counts: all alerts, True Positive, Needs Review, Benign Positive, False Positive and
  alerts to escalate. Click a tile to show only those alerts; click it again to show all.
- **Filters**: free-text search (press `/` to jump to it), time range (24 hours, 7 days, 30 days, all), verdict,
  severity and escalation chips (click to show only, Shift+click to hide), sorting (newest, highest severity,
  highest confidence), a **SIEM** selector (all SIEMs or one; shown when there is more than one) and, under
  *More filters*, a confidence range. The address bar keeps the filters, so a
  bookmark or shared link opens the same view.
- **The alert list**: one row per alert with verdict, severity, rule, host, confidence, merged duplicates, an
  escalation flag, the time and a one-line summary. New alerts appear at the top as they are triaged.

Click an alert to open it: summary, key findings with the evidence they rely on, the best malicious and benign
explanations, recommended actions, information gaps, MITRE ATT&CK techniques, safety checks that changed the
verdict, a link to Kibana and the alert ID (click to copy). **Investigation trail** shows every step: each query
with its arguments and result, and every model turn.

Analysts and admins can use the 👍 / 👎 buttons, and pick the correct verdict on 👎. Feedback is shown to the model when similar alerts
come in later. If an analyst marked a similar alert True Positive, the new one is never closed automatically.

### Status bar

The thin bar under the navigation shows, on every page and for every edition, what Ardea is doing now:

- **Worker**: the alert it is investigating (rule and host, link to the alert), the current step such as
  *reading the process tree*, the step count and how long it has been working; or that it is waiting for alerts,
  answering a question, running a settings test, or waiting for the AI model.
- **Fetcher**: how many new alerts the last collection brought, which SIEMs could not be reached, and when the
  next collection is.
- **Queue**: how many alerts wait to be investigated, with an estimate from the last 20 investigations. Hover for
  how many wait for a retry and how long the oldest has waited.

A part turns red when something looks stuck: an investigation running far past its time limit, a worker that
has not reported for 3 minutes, or a collection more than 5 minutes overdue. Users limited to some SIEMs see only
their SIEMs' queue, and no rule or host names from other SIEMs.

### Ask about this alert

*Pro.* Analysts and admins can ask a follow-up question in the alert's **Ask about this alert** box, such as
"Did this account log on anywhere else that day?" or "Why was this not closed?". The worker answers between
alerts, from the original investigation's evidence (E1, E2, …) and at most 4 new read-only queries in the same
SIEM, under the same scope rules as the triage (new evidence: Q1, Q2, …). Every statement cites its evidence;
citations that do not exist are removed and the answer says so. An answer never changes the verdict, never
closes anything and never searches the web; questions and answers are kept with the alert, apart from its
investigation trail. Viewers can read the answers. At most 10 questions per user per 10 minutes.

### Users and roles

| Role | Can |
|---|---|
| **Viewer** | See alerts, verdicts and investigation trails. |
| **Analyst** | Everything a viewer can, plus give feedback on verdicts (👍 / 👎). |
| **Admin** | Everything an analyst can, plus manage users. |

Admins manage accounts on the **Users** page: create a user (with a generated one-time password that is shown
once), change a role, reset a password, disable, enable or delete an account. Every new or reset account must
choose its own password at its next sign-in, and a role change, reset or disable signs that user out everywhere.
Ardea always keeps at least one active admin, and admins cannot change, disable or delete their own account.
The same page shows recent account activity: sign-ins, failed attempts, lockouts and changes.

**SIEM access** (with [several SIEMs](#several-siems)): when you create a user, tick *All SIEMs* or only the SIEMs
they may see; change it later in the *SIEMs* column. A user sees only those SIEMs' alerts, counts, investigation
trails and SIEM filter, and can give feedback only on them. *All SIEMs* includes SIEMs added later; admins always
see every SIEM. Changing a user's SIEMs signs them out. Notifications (email / ntfy) are not filtered per user: they
go to the addresses in `.env`.

Sign-in protection:

- passwords are stored as scrypt hashes and must be at least 12 characters, without the username
- after 5 wrong passwords an account is locked for 15 minutes (`MAX_FAILED_LOGINS`, `LOCKOUT_MINUTES`)
- sessions end after 8 hours without activity and always after 24 hours (`SESSION_IDLE_MINUTES`,
  `SESSION_MAX_HOURS`); signing out ends the session on the server
- session cookies are HTTPS-only and not readable by scripts, and every change requires a per-session token

If nobody can sign in as an admin any more, reset a password from the server:

```bash
docker compose exec publisher python manage.py list-users
docker compose exec publisher python manage.py reset-password admin     # prints a new one-time password
```

### Inspecting the database

To inspect the queue and results:

```bash
docker exec -it Ardea_postgres psql -U <POSTGRES_USER> -d <POSTGRES_DB>
```
```sql
SELECT status, count(*) FROM alerts GROUP BY 1;            -- new / processing / retry / done / failed
SELECT verdict, count(*) FROM triage_results GROUP BY 1;
SELECT alert_id, last_error FROM alerts WHERE status = 'failed' ORDER BY timestamp DESC LIMIT 20;
```

An alert is never dropped. After 3 failed attempts it is published as *Needs Human Review* with the reason. If
Ollama is unreachable, alerts wait in the queue until it is back.

---

## True Positive notifications

*Pro and MSP editions.*

Notifications are off until `NOTIFY_CHANNELS` is set. Each one is saved together with the verdict and delivered
with retries (from 30 s up to 1 h apart, 8 attempts), so a mail outage delays a notification but cannot lose it.
Only verdicts stored after you turn notifications on are sent.

1. **Choose the channels**: `smtp` (plain-text email), `ntfy` (push notifications to your phone), or both. A
   self-hosted ntfy server keeps alert details on your network. With Microsoft 365, enable *Authenticated SMTP*
   for the sending mailbox (Exchange admin center → the mailbox → *Manage email apps*).
2. **Add the settings to `.env`:**
   ```ini
   NOTIFY_CHANNELS=smtp
   ARDEA_PUBLIC_URL=https://ardea.example.com
   SMTP_HOST=smtp.office365.com
   SMTP_PORT=587
   SMTP_SECURITY=starttls
   SMTP_USER=ardea@example.com
   SMTP_PASSWORD='the-password'
   SMTP_FROM=ardea@example.com
   SMTP_TO=soc@example.com,oncall@example.com
   ```
   For ntfy, add `ntfy` to `NOTIFY_CHANNELS` and set `NTFY_URL`, `NTFY_TOPIC` and, if your server uses access
   tokens, `NTFY_TOKEN`. On the public ntfy.sh, anyone who knows the topic name can read it, so make it long and
   random. High and Critical alerts are sent at the highest priority.
3. **Restart the worker and send a test message:**
   ```bash
   docker compose up -d worker
   docker compose exec worker python notifier.py          # prints "sent test via smtp"
   ```
4. **Check delivery** from time to time:
   ```sql
   SELECT status, count(*), max(last_error) FROM notifications GROUP BY 1;
   ```
   `pending` with an error is still being retried; `failed` has given up. After fixing the cause, resend them with
   `UPDATE notifications SET status='pending', attempts=0, next_attempt_at=NOW() WHERE status='failed';`

More options:

- `NOTIFY_VERDICTS=True Positive,Needs Human Review` together with `NOTIFY_MIN_SEVERITY=High` also reports serious
  alerts the model could not confirm. On CPU-only setups, many real attacks end up as *Needs Human Review*.
- `NOTIFY_DETAIL=minimal` sends only the verdict, severity, rule name and links, without hostnames, users or the
  summary. Use it when mail goes through a cloud provider.

---

## Incidents

*Pro and MSP editions.*

**Incidents** groups alerts that belong together. Two alerts join the same incident when they come from the
same SIEM and share a host or a user account, the second within an hour of the previous one on that host or
account. Chains are followed: a phishing alert on a laptop, a credential dump on the same laptop and a remote
logon to a server with the same account become one incident across two hosts. Service and machine accounts
(SYSTEM, `HOST$`, `LOCAL SERVICE`…) never link alerts, or everything would join one incident.

The **Incidents** page lists incidents with two or more alerts, those that need a person first, with their
time span, hosts, accounts and verdicts. An incident's page shows one timeline with every alert's verdict
and summary, the rules involved and the MITRE techniques found. In the alert list, an alert that is part of
an incident links to it. Every alert keeps its own verdict and evidence: grouping changes nothing about
triage.

**Closing an incident.** Analysts and admins can close an incident on its page (**Close this incident**), or
several at once from the list (tick them, *Close, with the outcome and note*). Choose the outcome (resolved,
false positive, expected activity, duplicate, risk accepted) and add a note. A closed incident moves from
*Need a person* to *Closed by a person*, and its page shows who closed it, when and why. With the queue on,
its alerts that need a person are resolved in the queue with the same note. An incident whose alerts were all
resolved in the queue or reviewed by an analyst counts as handled too. If a new alert that needs a person
joins a closed incident, it goes back to *Need a person*, marked *New alerts since it was closed*. **Reopen**
undoes a closure. Every close and reopen is kept in the incident's history.

---

## Queue and response deadlines

*Pro and MSP editions.* Deadlines are set under **Settings → Response deadlines**.

Every alert that needs a person (True Positive, Needs Human Review) gets a deadline from its severity,
counted from the alert's time: by default 1 hour for Critical, 4 hours for High, 24 hours for Medium and 3
days for the rest. The **Queue** page lists those alerts, most urgent first, with *Mine*, *Unassigned* and
*Everything open* views. Analysts and admins take an alert, assign it to a colleague who can see that SIEM,
mark it in progress and resolve it with a note. For bulk work, tick several alerts (or **All**) in the queue,
or tick incidents on the **Incidents** page to act on every alert that needs a person in them; an incident's
own page does the same for that incident. An alert also counts as done once an analyst gives feedback on its
verdict.

Teams that track work elsewhere can switch the queue off (**Use the queue** on the same Settings tab): the
Queue page, assignments, deadlines and overdue messages disappear, and nothing is deleted.

When an alert passes its deadline without being resolved, one message goes to the notification channels
(switch it off on the same Settings tab). Who did what is kept with each alert, and the incident page shows
it.

---

## NIS2 report drafts and incident export

*Pro and MSP editions.*

**NIS2 drafts.** On an incident's page, **Draft a NIS2 report** fills in the early warning (24 hours), the
incident notification (72 hours) and the final report (one month after the notification) from what the
investigation found: times, affected hosts and accounts, MITRE techniques, indicators of compromise quoted in
the evidence, recommended measures and resolution notes. Everything only a person can know (service impact,
users affected, cross-border impact) is marked `[TO COMPLETE: …]`. No language model writes the draft: it
repeats the investigation's own findings. Copy it or download it as text. Your organisation's name, contact
and authority go under **Settings → NIS2 reports**. It is a draft, not legal advice: your national
authority's form decides what is sent.

**Export.** **Export (ZIP)** downloads the incident as `report.md`, `timeline.csv`, `incident.json` and every
alert's full investigation trail with analyst feedback, for a customer, an auditor or the authorities.
**Print or save as PDF** prints the incident page without the console around it. Exports are recorded in
the audit log.

---

## Monitoring and handover digest

*Pro and MSP editions; watched hosts: MSP.* Set up under **Settings → Monitoring and digest**.

**Silent sources.** A SIEM that stops receiving events raises no alerts, so nobody notices. Every 15 minutes
the worker asks each SIEM, read-only, for its newest event. No events for 2 hours (adjustable; 0 turns it
off), or a SIEM that cannot be reached twice in a row, sends one warning to the notification channels and
shows a banner in the console until it recovers. Recovery is announced too.

**Watched hosts (MSP).** List hosts that must never go quiet, such as `dc-*` or `srv-sql-01`. When one sends
no events for an hour (adjustable), you are told: an endpoint agent that stops reporting can be a crash, a
shutdown, or an attacker disabling it.

**Handover digest.** Once a day at the hour you choose, a summary of the last 24 hours goes to the
notification channels (e-mail, ntfy, Slack, Teams, webhook): alerts triaged and closed, the rules closed most
often, what still waits for a person with the most severe first, incidents with several alerts, and sources
that went quiet. **Send a digest now** shows what it looks like.

---

## Reports and insights

*Pro and MSP editions.* Open **Insights** in the top menu.

- **Report**: for the last 7, 30 or 90 days or any month: alerts triaged, closed automatically, sent to a
  person, true positives (listed), analyst time saved, analyst agreement and how often closures were right,
  and the noisiest rules. **Print or save as PDF** gives a clean one-page report for management.
- **Trends**: verdicts per week for the last 12 weeks, analyst agreement and median time per alert.
- **Scheduled e-mails**: set `ARDEA_REPORTS=weekly` or `monthly` (and optionally `ARDEA_REPORT_TO`). The
  worker e-mails the key figures and a link to the full report on Monday or on the 1st, through your SMTP
  settings. Each report is sent once.

"Time saved" is an estimate: alerts closed automatically × `ARDEA_MINUTES_PER_ALERT` (default 10). Set it to
what a first look at an alert takes your analysts. Users restricted to some SIEMs only see those SIEMs'
figures.

### Rule-tuning advisor

*Insights → Rule tuning*, for analysts and admins. It lists alert patterns from the last 30 days (same rule,
program, parent program and account) that Ardea closed every time, at least 5 times, and no analyst disputed.
For each one it writes the matching Elastic **rule exception**, as a query and as JSON for the exceptions API.
Add it in Kibana → Security → Rules → the rule → Rule exceptions. Patterns of credential access, lateral
movement, impact and exfiltration rules, and any pattern that ever had a true positive or a review verdict,
are never suggested. Check each suggestion before adding it: an exception stops the rule from alerting on
that pattern.

Only alerts collected by this version have the process details the advisor needs.

### Suppressions

*Insights → Suppressions*, Pro, for analysts and admins. Rule tuning needs a change in Kibana; a suppression
stays inside Ardea. Suggestions come from your analysts' feedback, not from the model: a pattern (same rule,
program, parent program and account in one SIEM) that analysts called Benign or False Positive at least 3 times in
30 days, never a True Positive, with no unreviewed True Positive verdict and no high-impact tactic. Patterns the
model keeps sending for review come first, because they cost a person the most time.

Create one with a reason (shown on every alert it closes), the verdict, optionally only for the one host, and an
expiry (90 days by default, at most a year). A matching alert is closed at once without the model, with the
summary *Closed by suppression #n … (created by …, expires …)*, and sends no notification. Alerts with
credential access, lateral movement, impact or exfiltration tactics, or with text that tries to instruct the
model, are always investigated. The page shows how many alerts each suppression closed and when it last did;
**Revoke** ends one immediately. Creating and revoking are recorded in the audit log.

---

## Integrations

*Pro and MSP editions.* Add the channels you use to `NOTIFY_CHANNELS` (comma list) and fill in their settings
in `.env`. They use the same rules as e-mail: `NOTIFY_VERDICTS`, `NOTIFY_MIN_SEVERITY` and `NOTIFY_DETAIL`, and
every message is queued and retried.

| Channel | Settings | What arrives |
|---|---|---|
| `slack` | `SLACK_WEBHOOK_URL` (incoming webhook) | Message with the verdict and buttons to Ardea and Kibana |
| `teams` | `TEAMS_WEBHOOK_URL` (Workflows: *when a webhook request is received*, post a card) | Adaptive card |
| `webhook` | `WEBHOOK_URL`, optional `WEBHOOK_SECRET` | JSON `{"event": "ardea.verdict", "payload": {...}}`, signed with `X-Ardea-Signature: sha256=<HMAC>` |
| `jira` | `JIRA_URL`, `JIRA_USER`, `JIRA_API_TOKEN`, `JIRA_PROJECT`, `JIRA_ISSUE_TYPE` | One issue per verdict, labelled `ardea` |
| `thehive` | `THEHIVE_URL`, `THEHIVE_API_KEY` | One TheHive 5 alert per verdict (never twice for the same alert) |

Test them with `docker compose exec worker python notifier.py` (all configured channels) or
`... python notifier.py slack`. Alert text is untrusted, so it is escaped for each channel: it cannot create
links or mentions in Slack or Teams. With the egress lockdown, set `NOTIFY_PROXY=http://egress-proxy:3128` and
add the hosts you use (for example `hooks.slack.com`) to `egress-proxy/squid.conf`.

---

## Playbook pack

*Pro and MSP editions.*

The playbook pack adds ready-made playbooks (pre-collected evidence plus guidance on what is benign and what
is not) for 30 common, noisy Elastic prebuilt rules, such as *Suspicious MS Office Child Process*,
*Startup or Run Key Registry Modification*, *Svchost spawning Cmd* and *Whoami Process Activity*, plus
guidance per MITRE tactic.

**Installing it.** As an admin, open **Settings → Playbook pack** and click **Install the latest pack**. The
worker asks the Ardea pack server (`packs.ardeasecurity.com`) for the newest pack, sending only your licence
key (or offline licence) and the installed version, checks the pack's signature and uses it from the next
alert. With **Install new packs automatically** on (the default), it checks once a day and installs each
monthly update itself. The same tab shows which rules and tactics the installed pack covers, and its history:
remove the newest version to go back to the one before.

**Without internet access**, download the `.ardpack` file from your customer portal on another computer and
upload it on the same tab, or put it in `packs/`. With the egress lockdown, allow `packs.ardeasecurity.com`
in `egress-proxy/squid.conf` and set the proxy on the Licence tab.

The pack is signed: a modified pack is refused, because playbook text is shown to the model as trusted
guidance. Your own `worker/playbooks.yaml` always wins over the pack for the same rule or tactic, so you can
copy any playbook from the pack there and adapt it. Rule policies such as *Credential Access is never
closed automatically* in your file cannot be relaxed by the pack.

---

## Single sign-on

*Pro and MSP editions.*

Analysts can sign in through your identity provider (Authentik, Authelia, Keycloak with oauth2-proxy, ...)
instead of an Ardea password. Caddy asks the identity provider (`forward_auth`) and passes the username to
Ardea, which signs in the Ardea user with **exactly that username**. Accounts are not created
automatically: create each user on the **Users** page first, so you still decide who gets in and with which
role.

1. Uncomment the `forward_auth` block in [`caddy/Caddyfile`](caddy/Caddyfile) and point it at your identity
   provider. The header must arrive as `X-Ardea-User`; Caddy always removes that header from browser
   requests first, so it cannot be forged.
2. Set `ARDEA_SSO=true` in `.env` and run `docker compose up -d`.

Local passwords keep working as a fallback (for example while the identity provider is down). Signing out of
Ardea signs you straight back in while your identity provider session lasts; sign out there to end it.

---

## Per-customer setup (MSP)

*MSP edition.* Each SIEM in `siems/siems.json` can carry its own settings:

```json
{"id": "acme", "name": "Acme Ltd", "url": "...", "fetcher_api_key": "...", "worker_api_key": "...",
 "context": ["Acme backups run nightly as svc.acmebackup", "10.9.0.5 is Acme's vulnerability scanner"],
 "notify": {"smtp_to": ["soc@acme.example"], "slack_webhook_url": "https://hooks.slack.com/services/...",
            "teams_webhook_url": "", "webhook_url": "", "webhook_secret": ""},
 "report_to": ["it-manager@acme.example"]}
```

- **`context`**: environment facts the model uses only for this customer's alerts.
- **`siems/<id>.playbooks.yaml`**: playbooks for this customer only (same layout as `worker/playbooks.yaml`).
  They win over your general playbooks and the pack. A tactic you marked `never_auto_close` stays so.
- **`notify`**: this customer's verdicts also go to their own e-mail, Slack, Teams or webhook, in addition to
  your channels.
- **`report_to`**: with `ARDEA_REPORTS` set, this customer gets their own report e-mail, with only their
  alerts and under your brand name.
- **Customer portal**: create **viewer** accounts limited to the customer's SIEM (Users page). They see only
  their own alerts and their own Insights report.
- **Usage export**: Users page → `/admin/usage.csv?month=2026-11` gives alerts per customer per month, for
  your invoicing.
- **Settings templates**: *Settings → SIEMs → Settings templates*. Save the alerts index, event indices,
  facts, report recipients and alert e-mail that many customers share, then tick the SIEMs and **Apply**. Facts
  are added to each customer's own (or replace them, if the template says so); every other value set in the
  template replaces the customer's; empty fields are left alone. Mark one template to start every new SIEM from
  it. API keys and webhooks are never part of a template. Applying copies the values, so changing a template
  later changes nothing until you apply it again. (SIEMs from `siems/siems.json` are edited in that file.)

---

## Own branding

*MSP edition.* Set `ARDEA_BRAND_NAME` in `.env` and put your logo in `branding/` as `logo.png`, `logo.jpg`
or `logo.webp` (at most 512 KB; SVG is not accepted). Then run `docker compose up -d publisher`.

---

## Web search (optional)

Web search lets the model look up public indicators: IP and domain reputation, file hashes, CVEs, MITRE
techniques and well-known file names. It is the only feature that sends data to the internet, so it is off by
default and protected in several layers:

- the model cannot write free-text queries, only typed indicators, and every query is checked in code: hostnames,
  usernames, internal IPs and domains, paths, e-mail addresses and secrets are rejected
- results are reduced to titles and short snippets (pages are never opened) and are marked as untrusted data
- every query is logged in the `outbound_requests` table, with hourly and daily limits

### With SearXNG (free)

SearXNG is a self-hosted search engine that forwards queries to DuckDuckGo, Bing, Brave and Wikipedia
([`searxng/settings.yml`](searxng/settings.yml)). It is included as the optional `search` profile and has no
published port, so only the worker can use it.

1. **List what must never leave your network** in `.env`. Any query containing one of these is rejected:
   ```ini
   INTERNAL_DOMAINS=example.com,example.local,corp
   SENSITIVE_TERMS=example,<AD NetBIOS name>,<Microsoft 365 tenant name>,<customer names>,<project names>
   ```
2. **Turn on SearXNG in dry-run mode.** Queries are checked and logged, but nothing is sent:
   ```ini
   COMPOSE_PROFILES=search
   WEB_SEARCH_PROVIDER=searxng
   SEARXNG_URL=http://searxng:8080
   SEARXNG_SECRET=<output of: openssl rand -hex 32>
   WEB_SEARCH_DRY_RUN=true
   WEB_SEARCH_KINDS=ip,domain,hash,cve,mitre,filename
   ```
   ```bash
   docker compose up -d
   docker compose exec worker python -c "import websearch; print(websearch.search('MITRE ATT&CK T1202', 3)['result_count'])"
   ```
   The second command sends one generic test query to check that SearXNG works. It should print a number above 0.
3. **Review the logged queries for about a week:**
   ```sql
   SELECT created_at, alert_id, query FROM outbound_requests WHERE status = 'dry_run' ORDER BY created_at DESC;
   ```
   Add anything that identifies your organisation to `SENSITIVE_TERMS`, then run `docker compose up -d worker`.
4. **Block direct internet access from the worker** (below), then set `WEB_SEARCH_DRY_RUN=false` and run
   `docker compose up -d worker`.

The free-text kinds `command_pattern` and `error_text` are off by default. Add them to `WEB_SEARCH_KINDS` only after
a dry run with them shows clean queries.

### With the Brave Search API

Brave has its own index and a single API host, which is simpler to firewall. Get a key at
https://api-dashboard.search.brave.com, then set `WEB_SEARCH_PROVIDER=brave`, `BRAVE_API_KEY=...` and
`EGRESS_PROXY=http://egress-proxy:3128`, and add `egress` to `COMPOSE_PROFILES`. The bundled squid proxy
([`egress-proxy/squid.conf`](egress-proxy/squid.conf)) only allows HTTPS to `api.search.brave.com`.

### Blocking direct internet access

Docker containers can reach the internet by default. [`egress-proxy/firewall.sh`](egress-proxy/firewall.sh)
restricts the `lan` network (worker and fetcher) to Elasticsearch, Ollama and your mail server, and rejects
everything else. Web search then only works through SearXNG or the squid proxy. Run it as root on the Docker host
with IP addresses, not host names:

```bash
sudo ELASTIC=10.0.0.5:9200 OLLAMA=10.0.0.11:11434 SMTP=10.0.0.25:587 ./egress-proxy/firewall.sh
docker compose exec worker python -c "import requests; requests.get('https://example.com', timeout=5)"   # must fail
```

Docker recreates its firewall chain when it restarts, so run the script from a systemd unit with
`After=docker.service`. `sudo ./egress-proxy/firewall.sh --remove` removes the rules.

The `lan` and `egress` networks use `172.30.10.0/24` and `172.30.20.0/24`. If these clash with your network, change
`ARDEA_LAN_SUBNET` and `ARDEA_EGRESS_SUBNET` before the first start.

---

## Performance without a GPU

- Writing the verdict is the slowest part (600–900 tokens). Keep the ignore list and playbooks focused, so the
  model spends its time on alerts that matter.
- Keep `LLM_NUM_CTX` at `16384`. A larger context makes every prompt slower, and changing it reloads the model.
- On a server with two CPU sockets, compare `LLM_NUM_THREAD=12` and `24` (physical cores of one socket vs. both)
  with the evaluation below and keep the faster setting.
- On the Ollama server, `OLLAMA_FLASH_ATTENTION=1` and `OLLAMA_KV_CACHE_TYPE=q8_0` may help. Measure before
  keeping them.
- `VERIFY_CLOSURES=true` adds a short second check (10–20 s) before an alert is closed as False or Benign
  Positive. It catches wrong closures; turn it off only if Ardea cannot keep up with your alert volume.

### Which alert comes first, and bursts

**Most urgent first.** The worker does not take alerts in arrival order. Each alert gets a priority from its
rule's risk score in Elastic (Low 21, Medium 47, High 73, Critical 99), plus 20 for credential access, lateral
movement, impact or exfiltration. The highest goes first. An alert gains a point for every 5 minutes it waits
(at most 40), so a low alert is never forgotten behind a stream of high ones.

**Bursts.** When one rule fires on many computers with the same program and parent program (an RMM agent, a
software rollout, a scanner), Ardea investigates the first three. If all three got the same verdict, the rest of
the burst reuses it within seconds, with the investigated alerts named in the summary, instead of waiting hours
for the model. A True Positive is never reused, and neither are alerts with a high-impact tactic or text that
tries to instruct the model. Nothing is reused once an analyst disagreed with a verdict of the burst, and every
25th reused alert is investigated in full again. *Settings → How alerts are handled → Handle bursts quickly*
switches it off; the numbers are under Advanced.

### A second worker for questions and tests

`docker compose up -d` also starts **worker-tasks**, a second copy of the worker that only runs the Settings
page tests and answers analysts' questions (*Ask about this alert*). They no longer wait until the current
investigation is finished. It never investigates alerts. If it is not running, the main worker does these
tasks between alerts as before. Both use the same Ollama: start Ollama with `OLLAMA_NUM_PARALLEL=2` (it needs
more memory) to answer a question while an alert is being investigated; otherwise the question waits only for
the investigation's current model step.

---

## Backups and system health

**Backups.** The `backup` service saves the whole database and the key that opens saved passwords every night
at 02:00 into the `backups` folder next to `docker-compose.yml`, and deletes backups older than 14 days. Change
the time and the number of days, or press **Back up now**, under *Settings → Backups*, which also lists every
backup and whether it worked. A backup on the same disk does not survive a broken disk: copy the `backups`
folder to another machine or a NAS now and then (for example with a nightly `rsync`).

Backups stay on your server. Ardea never sends them anywhere, and we never receive a copy. Anyone who has the
`backups` folder can read all of Ardea's data and the passwords saved on the Settings page, so keep it as safe
as the server itself.

To go back to a backup (everything stored after it is lost):

```bash
./backup/restore.sh backups/ardea-2026-11-20_0200.dump
```

It asks for confirmation, stops Ardea, replaces the database (and the settings key, from the `.keys.tgz` file
next to the dump), and starts Ardea again.

**System health** (*Settings → System health*, admins) shows on one page whether the worker, the fetcher and the
second worker are running, whether Ollama answers and which model it has loaded (and how much of it is on the
graphics card), how many alerts are waiting and how many hours of work that is, free disk space, the database
size and the last backup. The worker updates it every 5 minutes and warns your team through *Alerts to your
team*, at most once a day per problem, when the disk is nearly full (under 10% or 5 GB free), the last backup
failed or is more than 36 hours old, or more than 8 hours of work is waiting. The same problems appear on
*Settings → Start here*.

### Support bundle

When you ask for help, a support bundle saves a lot of back and forth. On the Docker host, in the Ardea folder:

```bash
./support-bundle.sh          # last 72 hours of logs; ./support-bundle.sh 24 for the last 24 hours
```

It saves one file, `ardea-support-<date>.tar.gz`, with the logs of every container, the versions of Ardea,
Docker and the database, the server's memory and disk, *System health*, the last backups, the licence state
and the queue size. Settings are listed by name: plain values are shown, secrets only as "set" or "empty".

Passwords, API keys, tokens, webhook addresses, the secrets saved on the Settings page and the secrets in `.env`
and `siems/siems.json` are replaced with `[REDACTED]` before the file is saved. If a known secret were still
in it, no file is saved at all. The logs can still contain names of your computers, users and alerts, so look
inside (`tar -xzf ardea-support-*.tar.gz`) before you send it. Nothing is sent anywhere by the command itself.

---

## Testing and evaluation

The worker tests need no model, database or SIEM:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r worker/requirements.txt pytest
pytest eval/ -q
```

The web UI tests (sign-in, roles, sessions, user management) run against a real, empty Postgres database whose
name ends in `_test`, after loading `db/init.sql` into it:

```bash
pip install -r publisher/requirements.txt pytest
POSTGRES_HOST=... POSTGRES_USER=... POSTGRES_PASSWORD=... POSTGRES_DB=ardea_test pytest publisher/tests -q
POSTGRES_HOST=... POSTGRES_USER=... POSTGRES_PASSWORD=... POSTGRES_DB=ardea_test pytest eval/test_licensing_db.py -q
```

The evaluation runs labelled alerts through the real model, with recorded SIEM results, and reports accuracy,
missed true positives, auto-close precision and prompt-injection failures:

```bash
python eval/run_eval.py --cases eval/samples/cases --llm http://<ollama-host>:11434 --model <model>
```

Once analysts have given feedback in the UI, build an evaluation set from your own alerts (Pro and MSP):

```bash
docker compose exec worker python export_eval_cases.py --out /tmp/cases
docker cp Ardea_worker:/tmp/cases/. eval/cases/          # git-ignored: contains real alert data
python eval/run_eval.py --llm http://<ollama-host>:11434 --model <model> --out eval/results/baseline.json
```

To measure what the playbook pack changes, add `--packs packs/`. After changing the model, prompts, playbooks or settings, run it again with
`--compare eval/results/baseline.json`. It fails if a true positive is missed or a metric gets worse.

For development with live code changes:
`docker compose -f docker-compose.yml -f docker-compose.dev.yml up`.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Worker log: `LLM not reachable ... waiting` | Ollama is down or unreachable. Alerts wait in the queue. Check `curl http://<ollama-host>:11434/api/tags` from the Docker host. |
| Worker log: `model ... is not installed` | `LLM_MODEL` must match `ollama list` exactly. |
| Alerts fail with `SiemError ... permission denied` | The API key expired or lacks index privileges. Recreate it from `elastic/roles.json`. |
| Alerts fail with `SSLError` | Elasticsearch uses a private CA: mount the CA file into the containers and set `ELASTIC_CA_CERT` (one SIEM), or put it in `siems/` and set `ca_cert` (several SIEMs). |
| Fetcher or worker exits with `siems.json ...` | The file is invalid; the message names the entry. `PermissionError`: run `sudo chown 10001 siems/siems.json`. |
| Fetcher log: `[<id>] fetch failed` | That cluster is unreachable or its key is wrong. The other SIEMs keep being collected. |
| Verdict *SIEM '<id>' is no longer configured* | The alert's SIEM was removed from `siems.json` (or disabled) before it was triaged. |
| Each alert takes far longer than a few minutes | Check that Ollama keeps the model loaded (`ollama ps`) and that nothing else uses it at the same time. |
| Browser warns about the certificate | Install Caddy's root certificate on that machine (step 4), or use your own certificate. Check that the address you typed is in `ARDEA_SITE_ADDRESS`. |
| Anything else, or you are not sure | Make a support bundle (`./support-bundle.sh`, see [Support bundle](#support-bundle)) and send it to support@ardeasecurity.com with a short description. |
| Lost admin password | `docker compose exec publisher python manage.py reset-password admin` |
| "Wrong username or password, or the account is locked" for a correct password | The account is locked after failed attempts (15 minutes) or was disabled; an admin can see it on the Users page and reset it. |
| Worker restarts with `NOTIFY_CHANNELS has unknown channel(s)` | Only `smtp` and `ntfy` are valid. |
| Many *Needs Human Review* verdicts for one rule | Add a playbook and `context:` facts for that rule, and give feedback in the UI. |
| Users page shows *Licence check: licence server not reachable* | The worker cannot reach `api.polar.sh`. Paid features stay on for 30 days. Set `ARDEA_LICENSE_PROXY` (egress lockdown) or allow the host. |
| *licence key not accepted: ... activation limit* | The key is active on another installation. Deactivate the old one in the customer portal (link in your purchase e-mail), then click **Check the licence now**. |
| Worker log: `playbook pack ... rejected: signature is not valid` | The pack file was changed or damaged. Download it again from your customer portal, or click **Install the latest pack**. |
| *Install the latest pack*: "The pack server is not reachable" | The worker cannot reach `packs.ardeasecurity.com`. Set the proxy on the Licence tab (egress lockdown), or upload the pack file instead. |
| SSO: *has no active Ardea account* | Create an Ardea user with exactly the username your identity provider sends, or enable the disabled account. |

---

## Licence

Ardea is source-available under the [Elastic License 2.0](LICENSE): free to use and modify, including in
your company; not to be offered as a hosted or managed service to others, and the licence checks must not be
removed or bypassed. The Pro and MSP editions and the playbook pack are covered by [EULA.md](EULA.md), which
also allows MSPs to run Ardea for their customers. See [NOTICE](NOTICE) for third-party components.

Questions, licences and security reports: support@ardeasecurity.com.
