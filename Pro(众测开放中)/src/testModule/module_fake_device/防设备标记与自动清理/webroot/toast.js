
/** ===== Toast ===== */
let toastTimer = null;
let toastSeq = 0;
function showToast(msg, kind = "success", durationMs = 1800) {
  toastSeq++;
  const mySeq = toastSeq;

  const el = els.toast;
  el.classList.remove("toast--success", "toast--danger", "toast--show");
  el.classList.add(kind === "danger" ? "toast--danger" : "toast--success");
  els.toastText.textContent = msg;
  el.offsetHeight;
  el.classList.add("toast--show");

  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    if (mySeq !== toastSeq) return;
    el.classList.remove("toast--show");
  }, durationMs);
}
