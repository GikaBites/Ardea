(function () {
	"use strict";
	for (const field of document.querySelectorAll("[data-autosubmit]")) {
		field.addEventListener("change", () => {
			const form = field.form;
			// a chosen month replaces the rolling range, and the other way round
			if (field.name === "month" && field.value) form.querySelector("[name=range]")?.setAttribute("disabled", "");
			if (field.name === "range") form.querySelector("[name=month]")?.setAttribute("disabled", "");
			form.submit();
		});
	}
	document.querySelector("[data-print]")?.addEventListener("click", () => window.print());
	document.addEventListener("click", (event) => {
		const btn = event.target.closest("[data-copy]");
		if (!btn) return;
		navigator.clipboard?.writeText(btn.dataset.copy).then(() => {
			const old = btn.textContent;
			btn.textContent = "Copied";
			window.setTimeout(() => { btn.textContent = old; }, 1200);
		});
	});
})();
