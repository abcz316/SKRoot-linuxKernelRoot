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
// 后端不解码 base64，应用名(UTF-8)在这里解码；解码失败返回空串
function decodeBase64Utf8(b64){
  if(!b64) return '';
  try{
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for(let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }catch(e){
    return '';
  }
}

// 解析候选列表：{"content":[{packageName,labelBase64}]}，后端不解码 base64，这里解码
function parseCandidates(json){
  let data;
  try{ data = JSON.parse(json); }catch(e){ return []; }
  const list = (data && Array.isArray(data.content)) ? data.content : [];
  return list.map(item => {
    const pkg = item.packageName || '';
    return { packageName: pkg, appName: decodeBase64Utf8(item.labelBase64) || pkg };
  });
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
// 目标包列表唯一格式：["pkg1","pkg2",...]，与后端 parse_json 保持一致
function normalizePkgs(arr){
  if (!Array.isArray(arr)) return [];
  const out = [];
  for (const s of arr){
    if (typeof s === "string"){
      const str = s.trim();
      if (str) out.push(str);
    }
  }
  return uniqKeepOrder(out);
}

async function syncTargets() {
  try {
    els.barSub.textContent = `条数：${pkgs.length}（同步中…）`;
    const json = JSON.stringify(pkgs);
    const info = await RequestApi.setTargetPkgJson(json);
    els.barSub.textContent = `条数：${pkgs.length}`;
    if(info == "OK") showToast("已生效", "success");
    else alert('已保存成功，需要重启手机后生效');
    
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
    const pkg = pkgs[i];
	
    const cand = candidates.find(c => c.packageName === pkg);
    const appName = ((cand && cand.appName) || "").trim() || pkg;

    // 提取首字母
    const initial = appName.charAt(0);

    const row = document.createElement("div");
    row.className = "row-item";
	
    const leftWrap = document.createElement("div");
    leftWrap.className = "cand-left-wrap";

    const avatar = document.createElement("div");
    avatar.className = "cand-avatar";
    avatar.textContent = initial;

    const left = document.createElement("div");
    left.className = "left";
	
    left.innerHTML = `
      <div class="app-name">${escapeHtml(appName)}</div>
      <div class="pkg" style="font-size: 12px; color:#9ca3af;">${escapeHtml(pkg)}</div>
    `;

    leftWrap.appendChild(avatar);
    leftWrap.appendChild(left);
	
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
    row.appendChild(leftWrap);
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
    const pkg = it.packageName;
	const name = (it.appName ?? "") + "";
    if (!kw) return true;
    return pkg.toLowerCase().includes(kw) || name.toLowerCase().includes(kw);
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
    const pkg = it.packageName;
    const appName = it.appName || pkg;
	
	const initial = appName.charAt(0);

    const row = document.createElement("div");
    row.className = "cand-item";
	
	const leftWrap = document.createElement("div");
    leftWrap.className = "cand-left-wrap";
	
	const avatar = document.createElement("div");
    avatar.className = "cand-avatar";
    avatar.textContent = initial;

    const left = document.createElement("div");
    left.className = "name";
    left.innerHTML = `
      <div class="app-name" style="font-size: 14px; font-weight: 600; color: #212121; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(appName)}</div>
      <div class="pkg" style="font-size: 12px; font-weight: normal; color: #9e9e9e;">${escapeHtml(pkg)}</div>
    `;
	
	leftWrap.appendChild(avatar);
    leftWrap.appendChild(left);

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

    row.appendChild(leftWrap);
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
      candidates = parseCandidates(await RequestApi.getCandidatesPkgJson());
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
    const pkg = it.packageName;
    const name = (it.appName ?? "") + "";
    if (!kw || pkg.toLowerCase().includes(kw) || name.toLowerCase().includes(kw)) {
      candSelected.add(pkg);
    }
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
	const [candData, targetData] = await Promise.all([
	  RequestApi.getCandidatesPkgJson().catch(()=>"[]"),
	  RequestApi.getTargetPkgJson().catch(()=>null)
	]);
	candidates = candData ? parseCandidates(candData) : [];
	let targetArr = null;
	try { targetArr = targetData ? JSON.parse(targetData) : null; } catch(e) { targetArr = null; }
	pkgs = normalizePkgs(targetArr);
    lastSyncedPkgs = pkgs.slice();   
    refreshUI();
  }catch(e){
    els.barSub.textContent = "加载失败";
    const msg = (e && e.message) ? e.message : "加载失败";
    showToast("加载失败：" + msg, "danger");
  }
})();