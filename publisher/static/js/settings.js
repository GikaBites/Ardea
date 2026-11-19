// Settings page: test buttons, fields that appear only when needed, the password pop-up, unsaved changes.
(function () {
	"use strict";
	const csrf = document.querySelector('meta[name="csrf-token"]');
	const token = csrf ? csrf.getAttribute("content") : "";
	const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

	// ------------------------------------------------------------------ test buttons
	// A test is queued for the worker (only it can open the saved secrets), then polled until it finishes.
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
					out.textContent = (res.status === "ok" ? "✓ " : "✗ ") + (res.detail || (res.status === "ok" ? "OK" : "Failed"));
					if (button.dataset.reload) setTimeout(() => window.location.reload(), 2500);
					return;
				}
				if (i === 10) out.textContent = "Still waiting: Ardea is probably busy with an alert…";
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

	// ------------------------------------------------------------------ fields shown only when needed
	// data-show-if="NAME=a|b": shown when the setting NAME (select, switch or ticked boxes) has one of the values.
	function valueOf(form, name) {
		const els = form.querySelectorAll(`[name="${name}"]`);
		const vals = [];
		els.forEach((el) => {
			if (el.type === "checkbox") { if (el.checked) vals.push(el.value); else if (els.length === 1) vals.push("false"); }
			else if (el.type === "radio") { if (el.checked) vals.push(el.value); }
			else vals.push(el.value);
		});
		return vals;
	}
	function refresh(form) {
		form.querySelectorAll("[data-show-if]").forEach((el) => {
			const [name, want] = el.dataset.showIf.split("=");
			if (el.closest(".set-channel")) return;          // channel cards handle their own fields
			const have = valueOf(form, name);
			el.hidden = !want.split("|").some((w) => have.includes(w));
		});
		form.querySelectorAll(".set-channel").forEach((card) => {
			const on = card.querySelector(".set-channel__head input").checked;
			card.classList.toggle("is-on", on);
			card.querySelector(".set-channel__body").hidden = !on;
		});
	}

	// ------------------------------------------------------------------ unsaved changes
	let dirty = false;
	function markDirty(form) {
		dirty = true;
		const note = form.querySelector(".set-dirty");
		if (note) note.hidden = false;
	}
	window.addEventListener("beforeunload", (ev) => {
		if (dirty) { ev.preventDefault(); ev.returnValue = ""; }
	});

	// ------------------------------------------------------------------ the password pop-up
	const page = document.querySelector(".set-layout");
	const needsPassword = page && page.dataset.needsPassword === "true";
	const dialog = document.getElementById("pw-dialog");

	function changedSensitive(form) {
		return Array.from(form.querySelectorAll("[data-sensitive]")).some((el) => {
			if (el.disabled) return false;
			if (el.type === "checkbox") return el.checked;
			if (el.type === "file") return el.files && el.files.length > 0;
			if (el.type === "password") return el.value.trim() !== "";
			return el.value !== el.defaultValue;
		});
	}
	function needsConfirm(form) {
		if (!needsPassword || !form.dataset.password) return false;
		if (form.dataset.password === "always") return true;
		return changedSensitive(form);
	}
	function askPassword(form) {
		const input = document.getElementById("pw-input");
		const err = document.getElementById("pw-error");
		const ok = document.getElementById("pw-ok");
		input.value = "";
		err.hidden = true;
		dialog.showModal();
		input.focus();
		const close = () => { dialog.close(); ok.onclick = null; input.onkeydown = null; };
		document.getElementById("pw-cancel").onclick = close;
		const confirm = async () => {
			ok.disabled = true;
			err.hidden = true;
			try {
				const r = await fetch("/admin/settings/confirm-password", {
					method: "POST", credentials: "same-origin",
					headers: { "X-CSRF-Token": token, "Content-Type": "application/json" },
					body: JSON.stringify({ password: input.value }),
				});
				if (r.ok) {
					let hidden = form.querySelector('input[name="confirm_password"]');
					if (!hidden) {
						hidden = document.createElement("input");
						hidden.type = "hidden";
						hidden.name = "confirm_password";
						form.appendChild(hidden);
					}
					hidden.value = input.value;
					close();
					dirty = false;
					form.dataset.confirmed = "1";
					form.requestSubmit ? form.requestSubmit() : form.submit();
					return;
				}
				err.textContent = r.status === 403 ? "That password is not correct. Nothing was saved: try again." :
					`Could not check the password (HTTP ${r.status}).`;
				err.hidden = false;
				input.select();
			} catch (e) {
				err.textContent = `Could not check the password: ${e.message}`;
				err.hidden = false;
			} finally {
				ok.disabled = false;
			}
		};
		ok.onclick = confirm;
		input.onkeydown = (ev) => { if (ev.key === "Enter") { ev.preventDefault(); confirm(); } };
	}

	document.querySelectorAll("form").forEach((form) => {
		if (form.closest(".set-layout") === null && form.id !== "pw-dialog") return;
		refresh(form);
		form.addEventListener("change", () => { refresh(form); if (form.classList.contains("set-form")) markDirty(form); });
		form.addEventListener("input", () => { if (form.classList.contains("set-form")) markDirty(form); });
		form.addEventListener("submit", (ev) => {
			if (form.dataset.confirmed !== "1" && dialog && needsConfirm(form)) {
				ev.preventDefault();
				askPassword(form);
				return;
			}
			dirty = false;
		});
	});
})();
