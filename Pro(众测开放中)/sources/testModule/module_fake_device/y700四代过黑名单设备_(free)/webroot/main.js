/** ===== 状态 ===== */
let pkgs = [];
let candidates = [];
let candSelected = new Set();

// 同步相关：最后一次成功同步的快照（用于失败回滚）
let lastSyncedPkgs = [];
let syncInFlight = 0;

const els = {
  pkgList: document.getElementById("pkgList"),
  emptyTips: document.getElementById("emptyTips"),
  countText: document.getElementById("countText"),
  barSub: document.getElementById("barSub"),

  btnPick: document.getElementById("btnPick"),

  toast: document.getElementById("toast"),
  toastText: document.getElementById("toastText"),

  pickMask: document.getElementById("pickMask"),
  pickMini: document.getElementById("pickMini"),
  pickSearch: document.getElementById("pickSearch"),
  pickAll: document.getElementById("pickAll"),
  pickClear: document.getElementById("pickClear"),
  candList: document.getElementById("candList"),
  pickSelCount: document.getElementById("pickSelCount"),
  pickOk: document.getElementById("pickOk"),
  btnPickClose: document.getElementById("btnPickClose"),
};

/** ===== 工具 ===== */
function escapeHtml(s){
  return String(s ?? "")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}
function uniqKeepOrder(arr){
  const seen = new Set();
  const out = [];
  for (const x of arr){
    if (!seen.has(x)){
      seen.add(x);
      out.push(x);
    }
  }
  return out;
}
function normalizePkgs(arr){
  return uniqKeepOrder((arr || []).map(s => (s || "").trim()).filter(Boolean));
}
function sameArray(a, b){
  if (a.length !== b.length) return false;
  for (let i=0;i<a.length;i++) if (a[i] !== b[i]) return false;
  return true;
}

async function syncTargets() {
  try {
    els.barSub.textContent = `条数：${pkgs.length}（同步中…）`;
    const json = JSON.stringify(pkgs);
    await RequestApi.setTargetPkgJson(json);
    els.barSub.textContent = `条数：${pkgs.length}`;
    showToast("重启后生效", "success");
  } catch (e) {
    els.barSub.textContent = `条数：${pkgs.length}（同步失败）`;
    showToast("同步失败", "danger");
  }
}

/** ===== UI ===== */
function refreshUI(){
  const n = pkgs.length;
  els.countText.textContent = String(n);
  els.barSub.textContent = `条数：${n}`;
  els.emptyTips.style.display = (n === 0) ? "block" : "none";
  renderPkgList();
}

function renderPkgList(){
  els.pkgList.innerHTML = "";
  for (let i=0; i<pkgs.length; i++){
    const p = pkgs[i];

    const row = document.createElement("div");
    row.className = "row-item";

    const left = document.createElement("div");
    left.className = "left";
    left.innerHTML = `<div class="pkg">${escapeHtml(p)}</div>`;

    const right = document.createElement("div");
    right.className = "right";

    const btnDel = document.createElement("button");
    btnDel.className = "danger";
    btnDel.textContent = "删除";
    btnDel.addEventListener("click", async (e) => {
      e.stopPropagation();

      // 先改前端
      pkgs.splice(i, 1);
      refreshUI();

      // 同步后台
      await syncTargets();
    });

    right.appendChild(btnDel);
    row.appendChild(left);
    row.appendChild(right);
    els.pkgList.appendChild(row);
  }
}

/** ===== Modal 通用 ===== */
function openMask(maskEl){
  maskEl.style.display = "flex";
  maskEl.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
}
function closeMask(maskEl){
  maskEl.style.display = "none";
  maskEl.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
}

/** ===== 候选选择 ===== */
function updatePickCount(){
  els.pickSelCount.textContent = String(candSelected.size);
  els.pickOk.disabled = (candSelected.size === 0);
  els.pickMini.textContent = `候选：${candidates.length}，已选：${candSelected.size}`;
}
function renderCandidates(){
  const kw = (els.pickSearch.value || "").trim().toLowerCase();

  const list = candidates.filter(it => {
    const pkg = (it.pkg ?? it) + "";
    if (!kw) return true;
    return pkg.toLowerCase().includes(kw);
  });

  els.candList.innerHTML = "";
  if (list.length === 0){
    const empty = document.createElement("div");
    empty.className = "cand-item";
    empty.innerHTML = `<div class="name"><div class="pkg">无匹配结果</div></div>`;
    els.candList.appendChild(empty);
    return;
  }

  for (const it of list){
    const pkg = (it.pkg ?? it) + "";

    const row = document.createElement("div");
    row.className = "cand-item";

    const left = document.createElement("div");
    left.className = "name";
    left.innerHTML = `<div class="pkg">${escapeHtml(pkg)}</div>`;

    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = candSelected.has(pkg);
    cb.addEventListener("change", () => {
      if (cb.checked) candSelected.add(pkg);
      else candSelected.delete(pkg);
      updatePickCount();
    });

    row.addEventListener("click", (e) => {
      if (e.target === cb) return;
      cb.checked = !cb.checked;
      cb.dispatchEvent(new Event("change"));
    });

    row.appendChild(left);
    row.appendChild(cb);
    els.candList.appendChild(row);
  }
}

async function openPickModal(){
  candSelected.clear();
  openMask(els.pickMask);
  els.pickSearch.value = "";
  els.pickMini.textContent = "加载中…";
  els.pickOk.disabled = true;

  try{
    if (candidates.length === 0){
      candidates = JSON.parse(await RequestApi.getCandidatesPkgJson());
    }
    renderCandidates();
    updatePickCount();
  }catch(e){
    els.pickMini.textContent = "加载失败";
    showToast("加载失败", "danger");
  }
}
function closePickModal(){ closeMask(els.pickMask); }

els.btnPick.addEventListener("click", openPickModal);
els.btnPickClose.addEventListener("click", closePickModal);
els.pickMask.addEventListener("click", (e) => {
  if (e.target === els.pickMask) closePickModal();
});
els.pickSearch.addEventListener("input", () => renderCandidates());

els.pickAll.addEventListener("click", () => {
  const kw = (els.pickSearch.value || "").trim().toLowerCase();
  for (const it of candidates){
    const pkg = (it.pkg ?? it) + "";
    if (!kw || pkg.toLowerCase().includes(kw)) candSelected.add(pkg);
  }
  renderCandidates();
  updatePickCount();
});

els.pickClear.addEventListener("click", () => {
  candSelected.clear();
  renderCandidates();
  updatePickCount();
});

els.pickOk.addEventListener("click", async () => {
  if (candSelected.size === 0) return;

  const before = pkgs.length;
  pkgs = normalizePkgs(pkgs.concat(Array.from(candSelected)));
  const added = pkgs.length - before;

  refreshUI();
  closePickModal();

  if (added <= 0){
    showToast("没有新增", "success");
    return;
  }

  // 同步后台
  await syncTargets();
});

/** ===== 初始化 ===== */
(async function init(){
  els.barSub.textContent = "加载中…";
  try{
	const data = await RequestApi.getTargetPkgJson();
	pkgs = data ? normalizePkgs(JSON.parse(data)) : [];
    lastSyncedPkgs = pkgs.slice();
    refreshUI();
  }catch(e){
    els.barSub.textContent = "加载失败";
    const msg = (e && e.message) ? e.message : "加载失败";
    showToast("加载失败：" + msg, "danger");
  }
})();