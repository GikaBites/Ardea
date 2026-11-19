// The status bar under the navigation: what the worker and the fetcher are doing, and the alert queue.
(function () {
  "use strict";
  var root = document.getElementById("ar-status");
  if (!root) return;
  var timer = null;

  function clock(s) {
    if (s == null) return "";
    s = Math.max(0, s);
    var m = Math.floor(s / 60), r = s % 60;
    return m >= 60 ? Math.floor(m / 60) + ":" + ("0" + (m % 60)).slice(-2) + " h" : m + ":" + ("0" + r).slice(-2);
  }

  function dur(s) {
    if (s == null) return "";
    s = Math.max(0, s);
    if (s < 60) return s + " s";
    if (s < 3600) return Math.floor(s / 60) + " min " + (s % 60 ? (s % 60) + " s" : "");
    return Math.floor(s / 3600) + " h " + Math.floor((s % 3600) / 60) + " min";
  }

  function set(svc, level, text, title, progress, href, meta) {
    var el = root.querySelector('[data-svc="' + svc + '"]');
    if (!el) return;
    el.setAttribute("data-level", level);
    var t = el.querySelector(".ar-st__text");
    t.textContent = "";
    if (href) {
      var a = document.createElement("a");
      a.href = href;
      a.textContent = text;
      t.appendChild(a);
    } else {
      t.textContent = text;
    }
    el.title = title || text;
    var m = el.querySelector(".ar-st__meta");
    if (m) m.textContent = meta || "";
    var bar = el.querySelector(".ar-st__bar i");
    if (bar) {
      bar.style.width = progress == null ? "0" : Math.round(progress * 100) + "%";
      el.classList.toggle("is-busy", progress != null && level !== "bad");
    }
  }

  function render(d) {
    var w = d.worker, f = d.fetcher, q = d.queue;
    var wt = w.text, wtitle = w.text, wp = null, href = null, wmeta = "";
    if (w.state === "investigating" || w.state === "answering") {
      var phase = w.phase ? w.phase.charAt(0).toUpperCase() + w.phase.slice(1) : "";
      wt = (phase ? phase + ": " : "") + w.text;
      wmeta = (w.step != null ? "step " + Math.max(1, w.step) + "/" + w.max_steps + " · " : "") + clock(w.since);
      wtitle = (w.state === "investigating" ? "Investigating " : "") + w.text + (phase ? " (" + w.phase + ")" : "") +
        (w.step != null ? ", step " + Math.max(1, w.step) + " of up to " + w.max_steps : "") + ", for " + dur(w.since);
      wp = w.progress;
      if (w.alert_id) href = "/?q=" + encodeURIComponent(w.alert_id);
    } else if (w.since != null && w.state !== "idle") {
      wtitle = w.text + " (for " + dur(w.since) + ")";
    }
    set("worker", w.level === "ok" && w.state === "idle" ? "idle" : w.level, wt, wtitle, wp, href, wmeta);

    var ft = f.text, fp = null, fmeta = "";
    if (f.state === "idle" || f.state === "error") {
      if (f.next_in != null && f.next_in >= 0) fmeta = "next " + clock(f.next_in);
      fp = f.progress;
    }
    set("fetcher", f.level === "ok" && f.state === "idle" ? "idle" : f.level, ft,
        ft + (f.next_in != null && f.next_in >= 0 ? ", next collection in " + dur(f.next_in) : "") +
        (f.last != null ? " (updated " + dur(f.last) + " ago)" : ""), f.state === "collecting" ? 0.5 : fp, null, fmeta);

    var qt, qtitle = [];
    if (!q.waiting) {
      qt = "empty";
    } else {
      qt = q.waiting + " waiting" + (q.eta_minutes ? " · ~" + (q.eta_minutes >= 120 ? Math.round(q.eta_minutes / 60) + " h" : q.eta_minutes + " min") : "");
      qtitle.push(q.ready + " ready to investigate");
      if (q.later) qtitle.push(q.later + " to retry later");
      if (q.oldest != null) qtitle.push("oldest waiting " + dur(q.oldest));
    }
    if (q.processing) qtitle.push(q.processing + " being investigated");
    set("queue", q.waiting > 50 ? "warn" : "ok", qt, "Alerts waiting to be investigated: " + (qtitle.join(", ") || "none"));
  }

  function tick() {
    if (document.hidden) return;
    fetch("/api/status", { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(render)
      .catch(function () {
        set("worker", "wait", "status unavailable", "The status could not be loaded", null);
      });
  }

  tick();
  timer = setInterval(tick, 5000);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) tick(); });
  window.addEventListener("pagehide", function () { clearInterval(timer); });
})();
