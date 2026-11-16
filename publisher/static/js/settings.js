// Settings page: the test buttons. A test is queued for the worker (only it can open the saved secrets),
// then polled until it finishes. Results are shown with textContent only.
(function () {
	"use strict";
	const csrf = document.querySelector('meta[name="csrf-token"]');
	const token = csrf ? csrf.getAttribute("content") : "";
	const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

	async function run(button) {
		const out = button.parentElement.querySelector(".set-test__result");
		button.disabled = true;
		out.className = "set-test__result is-wait";
		out.textContent = "Waiting for the worker…";
		try {
			const body = new URLSearchParams({ kind: button.dataset.test });
			const r = await fetch("/admin/settings/test", {
				method: "POST", body, credentials: "same-origin",
				headers: { "X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded" },
			});
			const start = await r.json().catch(() => ({}));
			if (!r.ok || !start.id) throw new Error(start.error || `HTTP ${r.status}`);
			for (let i = 0; i < 150; i++) {          // up to 5 minutes: the worker may be busy with an alert
				await sleep(i < 5 ? 1000 : 2000);
				const s = await fetch(`/admin/settings/test/${start.id}`, { credentials: "same-origin" });
				const res = await s.json().catch(() => ({}));
				if (res.status === "ok" || res.status === "failed") {
					out.className = `set-test__result is-${res.status}`;
					out.textContent = res.detail || (res.status === "ok" ? "OK" : "Failed");
					return;
				}
				if (i === 10) out.textContent = "Still waiting: the worker is probably investigating an alert…";
			}
			out.className = "set-test__result is-failed";
			out.textContent = "No answer from the worker. Is it running?";
		} catch (e) {
			out.className = "set-test__result is-failed";
			out.textContent = `Could not start the test: ${e.message}`;
		} finally {
			button.disabled = false;
		}
	}

	document.addEventListener("click", (ev) => {
		const b = ev.target.closest("button[data-test]");
		if (b) { ev.preventDefault(); run(b); }
	});
})();
