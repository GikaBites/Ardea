(function () {
	"use strict";

	let state;
	try {
		state = JSON.parse(document.getElementById("ardea-state").textContent);
	} catch {
		return;
	}

	const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
	const list = document.getElementById("alert-list");
	const searchInput = document.getElementById("q");
	const minConfidenceInput = document.getElementById("min_confidence");
	const maxConfidenceInput = document.getElementById("max_confidence");
	const sortSelect = document.getElementById("sort");
	const siemSelect = document.getElementById("siem");
	const emptyState = document.getElementById("empty-state");
	const sentinel = document.getElementById("load-more-sentinel");
	const totalCount = document.getElementById("total-count");
	const liveIndicator = document.getElementById("live-indicator");

	const VERDICT_KEY = {
		"True Positive": "tp",
		"Needs Human Review": "review",
		"Benign Positive": "benign",
		"False Positive": "fp",
	};
	const STANCE_LABEL = { suspicious: "Suspicious", benign: "Benign", neutral: "Neutral" };

	// ------------------------------------------------------------------ filter state
	const f = state.filters || {};
	const filters = {
		q: f.q || "",
		siem: f.siem || "",
		escalate: f.escalate || "",
		min_confidence: f.min_confidence || "",
		max_confidence: f.max_confidence || "",
		logic_mode: f.logic_mode || "and",
		range: f.range || "",
		sort: f.sort || "newest",
		includes: { verdict: new Set(f.includes?.verdict || []), severity: new Set(f.includes?.severity || []) },
		excludes: { verdict: new Set(f.excludes?.verdict || []), severity: new Set(f.excludes?.severity || []) },
	};

	let loadingOlder = false;
	let refreshTimer;
	let refreshController = null;
	let eventSource = null;

	// ------------------------------------------------------------------ helpers
	function sessionEnded(response) {
		if (response && (response.status === 401 || response.status === 403)) {
			window.location.assign("/login");
			return true;
		}
		return false;
	}

	function el(tag, cls, text) {
		const node = document.createElement(tag);
		if (cls) node.className = cls;
		if (text !== undefined && text !== null) node.textContent = String(text);
		return node;
	}

	function slug(value) {
		return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "-");
	}

	function timeAgo(iso) {
		if (!iso) return "";
		const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
		if (Number.isNaN(seconds)) return "";
		if (seconds < 60) return "just now";
		const minutes = Math.round(seconds / 60);
		if (minutes < 60) return `${minutes} min ago`;
		const hours = Math.round(minutes / 60);
		if (hours < 24) return `${hours} h ago`;
		const days = Math.round(hours / 24);
		return days === 1 ? "yesterday" : `${days} days ago`;
	}

	function buildParams() {
		const params = new URLSearchParams();
		if (filters.q) params.set("q", filters.q);
		if (filters.siem) params.set("siem", filters.siem);
		if (filters.escalate) params.set("escalate", filters.escalate);
		if (filters.min_confidence) params.set("min_confidence", filters.min_confidence);
		if (filters.max_confidence) params.set("max_confidence", filters.max_confidence);
		if (filters.logic_mode !== "and") params.set("logic_mode", filters.logic_mode);
		if (filters.range) params.set("range", filters.range);
		if (filters.sort !== "newest") params.set("sort", filters.sort);
		for (const key of ["verdict", "severity"]) {
			for (const v of filters.includes[key]) params.append(key, v);
			for (const v of filters.excludes[key]) params.append(`exclude_${key}`, v);
		}
		return params;
	}

	// ------------------------------------------------------------------ alert rows
	function section(title, ...children) {
		const box = el("section", "ar-section");
		box.appendChild(el("h4", "ar-section__title", title));
		for (const child of children) if (child) box.appendChild(child);
		return box;
	}

	function bulletList(items, render) {
		const ul = el("ul", "ar-bullets");
		for (const item of items) ul.appendChild(render(item));
		return ul;
	}

	function mitreLink(m) {
		if (!/^T\d{4}(\.\d{3})?$/.test(m.id)) return el("span", "ar-tag", `${m.id} ${m.name}`);
		const a = el("a", "ar-tag ar-tag--link", `${m.id} ${m.name}`);
		a.href = `https://attack.mitre.org/techniques/${m.id.replace(".", "/")}/`;
		a.target = "_blank";
		a.rel = "noopener noreferrer";
		return a;
	}

	function buildBody(alert) {
		const d = alert.detail || {};
		const body = el("div", "ar-alert__body");

		if (d.injection) {
			body.appendChild(el("div", "ar-warning",
				"The alert contains text that tried to manipulate the triage model. Treat with extra care."));
		}
		if (d.summary) body.appendChild(section("Summary", el("p", "ar-summary-full", d.summary)));

		const grid = el("div", "ar-grid");
		if (d.findings?.length) {
			grid.appendChild(section("Key findings", bulletList(d.findings, (finding) => {
				const li = el("li", `ar-finding ar-finding--${slug(finding.stance)}`);
				li.appendChild(el("span", "ar-stance", STANCE_LABEL[finding.stance] || finding.stance));
				li.appendChild(el("span", "ar-finding__claim", finding.claim));
				for (const id of finding.evidence || []) li.appendChild(el("span", "ar-evidence", id));
				return li;
			})));
		}
		const hyp = el("div", "ar-hypotheses");
		if (d.malicious) {
			const box = el("div", "ar-hyp ar-hyp--malicious");
			box.appendChild(el("div", "ar-hyp__label", "If malicious"));
			box.appendChild(el("p", "", d.malicious));
			hyp.appendChild(box);
		}
		if (d.benign) {
			const box = el("div", "ar-hyp ar-hyp--benign");
			box.appendChild(el("div", "ar-hyp__label", "If benign"));
			box.appendChild(el("p", "", d.benign));
			hyp.appendChild(box);
		}
		if (hyp.childElementCount) grid.appendChild(section("Explanations", hyp));
		if (grid.childElementCount) body.appendChild(grid);

		const grid2 = el("div", "ar-grid");
		if (d.actions?.length) {
			grid2.appendChild(section("Recommended actions", bulletList(d.actions, (a) => {
				const li = el("li", "ar-action");
				if (a.priority) li.appendChild(el("span", `ar-priority ar-priority--${slug(a.priority)}`, a.priority));
				li.appendChild(el("span", "", a.action));
				return li;
			})));
		}
		if (d.gaps?.length) {
			grid2.appendChild(section("Information gaps", bulletList(d.gaps, (g) => el("li", "", g))));
		}
		if (grid2.childElementCount) body.appendChild(grid2);

		if (d.mitre?.length) {
			const tags = el("div", "ar-tags");
			for (const m of d.mitre) tags.appendChild(mitreLink(m));
			body.appendChild(section("MITRE ATT&CK", tags));
		}
		if (d.guardrails?.length) {
			body.appendChild(section("Safety checks applied", bulletList(d.guardrails, (g) => el("li", "ar-muted", g))));
		}

		const footer = el("div", "ar-alert__footer");
		if (alert.post_url) {
			const a = el("a", "ar-button", state.multiSiem && alert.siem_name
				? `Open in Kibana (${alert.siem_name})` : "Open in Kibana");
			a.href = alert.post_url;
			a.target = "_blank";
			a.rel = "noopener noreferrer";
			footer.appendChild(a);
		}
		if (alert.incident) {                       // Pro: this alert is part of a larger incident
			const inc = el("a", "ar-button ar-button--incident", `Part of an incident: ${alert.incident[1]} alerts`);
			inc.href = `/incidents/${encodeURIComponent(alert.incident[0])}`;
			footer.appendChild(inc);
		}
		const idTag = el("button", "ar-id", `ID ${alert.alert_id.slice(0, 12)}…`);
		idTag.type = "button";
		idTag.title = "Copy the full alert ID";
		idTag.dataset.copy = alert.alert_id;
		footer.appendChild(idTag);
		const facts = [alert.timestamp, d.model, d.tool_calls != null ? `${d.tool_calls} tool calls` : "",
			d.duration_ms ? `${Math.round(d.duration_ms / 1000)} s` : ""].filter(Boolean);
		footer.appendChild(el("span", "ar-muted ar-mono", facts.join(" · ")));
		body.appendChild(footer);

		const trail = el("details", "ar-trail");
		trail.dataset.trailFor = alert.alert_id;
		trail.appendChild(el("summary", "", `Investigation trail${alert.steps ? ` (${alert.steps} steps)` : ""}`));
		trail.appendChild(el("div", "ar-trail__body"));
		body.appendChild(trail);

		if (state.canFeedback) body.appendChild(buildFeedback(alert));
		if (state.canRetriage) {
			const re = el("div", "ar-retriage");
			const btn = el("button", "ar-button", "Re-triage this alert");
			btn.type = "button";
			btn.dataset.retriage = alert.alert_id;
			re.appendChild(btn);
			re.appendChild(el("span", "ar-feedback__status"));
			body.appendChild(re);
		}
		return body;
	}

	function buildFeedback(alert) {
		const box = el("div", "ar-feedback");
		box.dataset.feedbackFor = alert.alert_id;
		box.appendChild(el("span", "ar-feedback__label", "Is this verdict right?"));
		const agree = el("button", "ar-button ar-button--good", "Yes, agree");
		agree.type = "button";
		agree.dataset.agree = "true";
		box.appendChild(agree);
		const select = el("select", "form-select form-select-sm ar-feedback__select");
		select.setAttribute("aria-label", "Correct verdict");
		select.appendChild(el("option", "", "No, it should be…")).value = "";
		for (const v of Object.keys(VERDICT_KEY)) {
			if (v !== alert.verdict) select.appendChild(el("option", "", v));
		}
		box.appendChild(select);
		box.appendChild(el("span", "ar-feedback__status"));
		return box;
	}

	function createAlertRow(alert) {
		const key = VERDICT_KEY[alert.verdict] || "unknown";
		const row = el("details", `ar-alert ar-alert--${key}`);
		row.dataset.alertId = alert.alert_id;

		const head = el("summary", "ar-alert__head");
		const badges = el("div", "ar-alert__badges");
		badges.appendChild(el("span", `ar-verdict ar-verdict--${key}`,
			alert.verdict === "Needs Human Review" ? "Needs Review" : alert.verdict));
		badges.appendChild(el("span", `ar-sev ar-sev--${slug(alert.severity)}`, alert.severity));
		head.appendChild(badges);

		const main = el("div", "ar-alert__main");
		const title = el("div", "ar-alert__title");
		title.appendChild(el("span", "ar-rule", alert.rule_name));
		title.appendChild(el("span", "ar-host", alert.hostname));
		if (state.multiSiem && alert.siem_name) {
			const siem = el("span", "ar-siem", alert.siem_name);
			siem.title = `SIEM: ${alert.siem_name}`;
			title.appendChild(siem);
		}
		main.appendChild(title);
		if (alert.detail?.summary) main.appendChild(el("p", "ar-alert__summary", alert.detail.summary));
		head.appendChild(main);

		// fixed slots, so confidence bars and times line up from row to row
		const meta = el("div", "ar-alert__meta");
		meta.appendChild(alert.should_escalate ? el("span", "ar-flag", "Escalate") : el("span", "ar-slot"));
		if (alert.occurrences > 1) {
			const occ = el("span", "ar-occ", `×${alert.occurrences}`);
			occ.title = `${alert.occurrences} identical alerts were merged into this one`;
			meta.appendChild(occ);
		} else {
			meta.appendChild(el("span", "ar-slot"));
		}
		if (alert.confidence_score === null || alert.confidence_score === undefined) {
			meta.appendChild(el("span", "ar-slot"));
		} else {
			const conf = el("span", "ar-conf");
			conf.title = `Confidence ${alert.confidence_score}%`;
			const bar = el("span", "ar-conf__bar");
			const fill = el("span", "ar-conf__fill");
			fill.style.setProperty("width", `${Math.max(0, Math.min(100, alert.confidence_score))}%`);
			bar.appendChild(fill);
			conf.appendChild(bar);
			conf.appendChild(el("span", "ar-conf__value", alert.confidence_score));
			meta.appendChild(conf);
		}
		const time = el("time", "ar-time", timeAgo(alert.timestamp_iso));
		time.dateTime = alert.timestamp_iso || "";
		time.title = alert.timestamp || "";
		meta.appendChild(time);
		head.appendChild(meta);
		head.appendChild(el("span", "ar-chevron"));

		row.appendChild(head);
		row.appendChild(buildBody(alert));
		return row;
	}

	function currentAlertIds() {
		return new Set(Array.from(list.querySelectorAll("[data-alert-id]"), (n) => n.dataset.alertId));
	}

	function topAlertId() {
		return list.querySelector("[data-alert-id]")?.dataset.alertId || "";
	}

	// ------------------------------------------------------------------ tiles, chips, counts
	function renderStats(stats) {
		if (!stats) return;
		for (const node of document.querySelectorAll("[data-count]")) {
			const k = node.dataset.count;
			const value = k === "total" ? stats.total : k === "escalate" ? stats.escalate : stats.verdicts?.[k];
			node.textContent = String(value ?? 0);
		}
	}

	function syncControls() {
		for (const chip of document.querySelectorAll("[data-filter-key]")) {
			const { filterKey: key, filterValue: value } = chip.dataset;
			chip.classList.toggle("is-include", filters.includes[key].has(value));
			chip.classList.toggle("is-exclude", filters.excludes[key].has(value));
			chip.setAttribute("aria-pressed", String(filters.includes[key].has(value)));
		}
		for (const chip of document.querySelectorAll("[data-escalate-value]")) {
			chip.classList.toggle("is-include", filters.escalate === chip.dataset.escalateValue);
		}
		for (const btn of document.querySelectorAll("[data-range]")) {
			btn.classList.toggle("is-active", btn.dataset.range === filters.range);
		}
		for (const btn of document.querySelectorAll(".logic-toggle")) {
			btn.classList.toggle("is-active", btn.dataset.logicValue === filters.logic_mode);
		}
		if (siemSelect) siemSelect.value = filters.siem;
		const onlyVerdict = filters.includes.verdict.size === 1 && filters.excludes.verdict.size === 0
			? [...filters.includes.verdict][0] : null;
		for (const tile of document.querySelectorAll("[data-tile]")) {
			let active = false;
			if (tile.dataset.tile === "verdict") active = onlyVerdict === tile.dataset.verdict;
			if (tile.dataset.tile === "escalate") active = filters.escalate === "true";
			if (tile.dataset.tile === "all") {
				active = !filters.includes.verdict.size && !filters.excludes.verdict.size && !filters.escalate;
			}
			tile.classList.toggle("is-active", active);
		}
	}

	// ------------------------------------------------------------------ loading
	async function refreshAlerts() {
		const params = buildParams();
		params.set("offset", "0");
		params.set("limit", String(state.pageSize));
		refreshController?.abort();
		const controller = new AbortController();
		refreshController = controller;
		let response;
		try {
			response = await fetch(`/api/alerts?${params}`, { signal: controller.signal });
		} catch {
			return;
		}
		if (controller.signal.aborted || sessionEnded(response) || !response.ok) return;
		const payload = await response.json();
		const alerts = payload.alerts || [];
		list.replaceChildren(...alerts.map(createAlertRow));
		emptyState.classList.toggle("d-none", alerts.length > 0);
		state.nextOffset = payload.next_offset;
		state.hasMore = Boolean(payload.has_more);
		sentinel.classList.toggle("d-none", !state.hasMore);
		totalCount.textContent = String(payload.total ?? 0);
		renderStats(payload.stats);
		const query = buildParams().toString();
		history.replaceState(null, "", query ? `/?${query}` : "/");
		restartLiveStream();
	}

	function scheduleRefresh(delay = 300) {
		window.clearTimeout(refreshTimer);
		refreshTimer = window.setTimeout(() => void refreshAlerts(), delay);
	}

	function applyChange() {
		syncControls();
		scheduleRefresh(0);
	}

	async function loadOlderAlerts() {
		if (loadingOlder || !state.hasMore) return;
		loadingOlder = true;
		try {
			const params = buildParams();
			params.set("offset", String(state.nextOffset));
			params.set("limit", String(state.pageSize));
			const response = await fetch(`/api/alerts?${params}`);
			if (sessionEnded(response) || !response.ok) return;
			const payload = await response.json();
			const known = currentAlertIds();
			for (const alert of payload.alerts || []) {
				if (!known.has(alert.alert_id)) list.appendChild(createAlertRow(alert));
			}
			state.nextOffset = payload.next_offset;
			state.hasMore = Boolean(payload.has_more);
			sentinel.classList.toggle("d-none", !state.hasMore);
		} finally {
			loadingOlder = false;
		}
	}

	// ------------------------------------------------------------------ live updates
	function setLive(stateName, text) {
		liveIndicator.dataset.state = stateName;
		liveIndicator.querySelector(".ar-live__text").textContent = text;
	}

	function startLiveStream() {
		const params = buildParams();
		const since = topAlertId();
		if (since) params.set("since_id", since);
		eventSource = new EventSource(`/stream?${params}`);
		eventSource.addEventListener("open", () => setLive("live", "Live"));
		eventSource.addEventListener("error", () => setLive("offline", "Reconnecting"));
		eventSource.addEventListener("logout", () => {
			eventSource.close();
			window.location.assign("/login");
		});
		eventSource.addEventListener("ping", () => setLive("live", "Live"));
		eventSource.addEventListener("alerts", (event) => {
			let payload;
			try {
				payload = JSON.parse(event.data);
			} catch {
				return;
			}
			setLive("live", "Live");
			renderStats(payload.stats);
			const known = currentAlertIds();
			let added = 0;
			for (const alert of (payload.alerts || []).slice().reverse()) {
				if (known.has(alert.alert_id)) continue;
				const row = createAlertRow(alert);
				row.classList.add("is-new");
				list.prepend(row);
				added += 1;
			}
			if (added) {
				emptyState.classList.add("d-none");
				totalCount.textContent = String(Number(totalCount.textContent || "0") + added);
			}
		});
	}

	function restartLiveStream() {
		eventSource?.close();
		eventSource = null;
		setLive("connecting", "Connecting");
		startLiveStream();
	}

	// ------------------------------------------------------------------ investigation trail
	function renderTrail(container, payload) {
		container.replaceChildren();
		const steps = payload.steps || [];
		if (!steps.length) {
			container.appendChild(el("div", "ar-muted", "No trail recorded for this alert."));
		}
		for (const s of steps) {
			const row = el("div", `ar-step ar-step--${slug(s.status)}`);
			const head = el("div", "ar-step__head");
			head.appendChild(el("span", "ar-mono ar-muted", `#${s.step}`));
			head.appendChild(el("span", "ar-step__kind", s.kind));
			if (s.tool_name) head.appendChild(el("span", "ar-step__tool", s.tool_name));
			head.appendChild(el("span", `ar-step__status ar-step__status--${slug(s.status)}`, s.status));
			if (s.evidence_id) head.appendChild(el("span", "ar-evidence", s.evidence_id));
			if (s.duration_ms) head.appendChild(el("span", "ar-mono ar-muted", `${s.duration_ms} ms`));
			row.appendChild(head);
			if (s.arguments) row.appendChild(el("code", "ar-step__args", JSON.stringify(s.arguments)));
			if (s.llm_content) row.appendChild(el("div", "ar-step__text", s.llm_content));
			if (s.error) row.appendChild(el("div", "ar-step__error", s.error));
			if (s.result) {
				const det = el("details");
				det.appendChild(el("summary", "ar-muted", "Result"));
				det.appendChild(el("pre", "ar-pre", JSON.stringify(s.result, null, 2)));
				row.appendChild(det);
			}
			container.appendChild(row);
		}
		for (const fb of payload.feedback || []) {
			container.appendChild(el("div", "ar-step ar-step--feedback",
				`Feedback by ${fb.analyst}: ${fb.agrees ? "agrees" : `should be ${fb.correct_verdict || "?"}`}${fb.comment ? ` · ${fb.comment}` : ""}`));
		}
	}

	list.addEventListener("toggle", async (event) => {
		const details = event.target;
		if (!(details instanceof HTMLDetailsElement) || !details.open || details.dataset.loaded) return;
		const id = details.dataset.trailFor;
		if (!id) return;
		const body = details.querySelector(".ar-trail__body");
		body.textContent = "Loading…";
		try {
			const r = await fetch(`/api/alerts/${encodeURIComponent(id)}/trail`);
			if (sessionEnded(r)) return;
			renderTrail(body, await r.json());
			details.dataset.loaded = "1";
		} catch {
			body.textContent = "Could not load the trail.";
		}
	}, true);

	// ------------------------------------------------------------------ feedback and copy
	async function sendFeedback(box, agrees, correct) {
		const status = box.querySelector(".ar-feedback__status");
		status.textContent = "Saving…";
		try {
			const r = await fetch(`/api/alerts/${encodeURIComponent(box.dataset.feedbackFor)}/feedback`, {
				method: "POST",
				headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
				body: JSON.stringify({ agrees, correct_verdict: correct || null }),
			});
			if (sessionEnded(r)) return;
			status.textContent = r.ok ? "Thanks, recorded." : `Error ${r.status}`;
			box.classList.toggle("is-saved", r.ok);
		} catch {
			status.textContent = "Network error";
		}
	}

	async function sendRetriage(btn) {
		const status = btn.parentElement.querySelector(".ar-feedback__status");
		btn.disabled = true;
		status.textContent = "Queuing…";
		try {
			const r = await fetch(`/api/alerts/${encodeURIComponent(btn.dataset.retriage)}/retriage`, {
				method: "POST",
				headers: { "X-CSRF-Token": csrfToken },
			});
			if (sessionEnded(r)) return;
			status.textContent = r.ok ? "Queued. The new verdict replaces this one in a few minutes."
				: r.status === 409 ? "Already queued." : `Error ${r.status}`;
		} catch {
			status.textContent = "Network error";
		}
		btn.disabled = false;
	}

	const exportLink = document.getElementById("export-csv");
	if (exportLink) {
		exportLink.addEventListener("click", () => {
			exportLink.href = "/api/alerts.csv" + window.location.search;
		});
	}

	list.addEventListener("click", (event) => {
		const retriageBtn = event.target.closest("[data-retriage]");
		if (retriageBtn) void sendRetriage(retriageBtn);
		const agree = event.target.closest("[data-agree]");
		if (agree) void sendFeedback(agree.closest("[data-feedback-for]"), true, null);
		const copy = event.target.closest("[data-copy]");
		if (copy) {
			navigator.clipboard?.writeText(copy.dataset.copy).then(() => {
				const old = copy.textContent;
				copy.textContent = "Copied";
				window.setTimeout(() => { copy.textContent = old; }, 1200);
			});
		}
	});
	list.addEventListener("change", (event) => {
		if (event.target.matches(".ar-feedback__select") && event.target.value) {
			void sendFeedback(event.target.closest("[data-feedback-for]"), false, event.target.value);
		}
	});

	// ------------------------------------------------------------------ controls
	for (const chip of document.querySelectorAll("[data-filter-key]")) {
		chip.addEventListener("click", (event) => {
			const { filterKey: key, filterValue: value } = chip.dataset;
			const target = event.shiftKey ? filters.excludes[key] : filters.includes[key];
			const other = event.shiftKey ? filters.includes[key] : filters.excludes[key];
			other.delete(value);
			if (target.has(value)) target.delete(value);
			else target.add(value);
			applyChange();
		});
	}
	for (const chip of document.querySelectorAll("[data-escalate-value]")) {
		chip.addEventListener("click", () => {
			filters.escalate = filters.escalate === chip.dataset.escalateValue ? "" : chip.dataset.escalateValue;
			applyChange();
		});
	}
	for (const btn of document.querySelectorAll("[data-range]")) {
		btn.addEventListener("click", () => {
			filters.range = btn.dataset.range;
			applyChange();
		});
	}
	for (const btn of document.querySelectorAll(".logic-toggle")) {
		btn.addEventListener("click", () => {
			filters.logic_mode = btn.dataset.logicValue;
			applyChange();
		});
	}
	for (const tile of document.querySelectorAll("[data-tile]")) {
		tile.addEventListener("click", () => {
			if (tile.dataset.tile === "all") {
				filters.includes.verdict.clear();
				filters.excludes.verdict.clear();
				filters.escalate = "";
			} else if (tile.dataset.tile === "escalate") {
				filters.escalate = filters.escalate === "true" ? "" : "true";
			} else {
				const v = tile.dataset.verdict;
				const alreadyOnly = filters.includes.verdict.size === 1 && filters.includes.verdict.has(v);
				filters.includes.verdict.clear();
				filters.excludes.verdict.clear();
				if (!alreadyOnly) filters.includes.verdict.add(v);
			}
			applyChange();
		});
	}
	siemSelect?.addEventListener("change", () => {
		filters.siem = siemSelect.value;
		applyChange();
	});
	sortSelect?.addEventListener("change", () => {
		filters.sort = sortSelect.value;
		applyChange();
	});
	searchInput?.addEventListener("input", () => {
		filters.q = searchInput.value.trim();
		scheduleRefresh();
	});
	for (const input of [minConfidenceInput, maxConfidenceInput]) {
		input?.addEventListener("input", () => {
			filters.min_confidence = minConfidenceInput.value.trim();
			filters.max_confidence = maxConfidenceInput.value.trim();
			scheduleRefresh(500);
		});
	}
	document.getElementById("filter-form").addEventListener("submit", (event) => {
		event.preventDefault();
		scheduleRefresh(0);
	});

	document.addEventListener("keydown", (event) => {
		const typing = event.target.matches("input, select, textarea");
		if (event.key === "/" && !typing) {
			event.preventDefault();
			searchInput?.focus();
		} else if (event.key === "Escape" && event.target === searchInput) {
			searchInput.value = "";
			filters.q = "";
			searchInput.blur();
			scheduleRefresh(0);
		}
	});

	// keep "12 min ago" labels current
	window.setInterval(() => {
		for (const t of list.querySelectorAll("time[datetime]")) t.textContent = timeAgo(t.dateTime);
	}, 60000);

	new IntersectionObserver((entries) => {
		if (entries.some((e) => e.isIntersecting)) void loadOlderAlerts();
	}, { rootMargin: "200px 0px" }).observe(sentinel);

	syncControls();
	void refreshAlerts();
})();
