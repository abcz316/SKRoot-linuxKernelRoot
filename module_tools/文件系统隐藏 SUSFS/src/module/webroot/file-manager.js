(() => {
  const app = window.SKRootApp || { elements: { fileBtn: document.getElementById('fileBtn') }, closeAllSheets() {} };
  const ui = window.SKUiUtils;
  const icons = window.SKIcons;
  const modelApi = window.SKFileManagerModel;
  if (!app || !ui || !icons || !modelApi) return;

  const { FileManagerModel, normalizePath, joinPath, parentPath, defaultZipName, symbolicMode, octalMode } = modelApi;
  const { fileBtn } = app.elements;
  const canUseSusfs = () => window.SKSusfsAvailability?.canAccess() === true;

  const elements = {
    workspace: document.getElementById("fileWorkspace"),
    close: document.getElementById("fileClose"),
    pathTrigger: document.getElementById("activePathTrigger"),
    pathText: document.getElementById("activePathText"),
    pathMeta: document.getElementById("activePathMeta"),
    pathEditor: document.getElementById("activePathEditor"),
    pathInput: document.getElementById("pathInput"),
    pathGo: document.getElementById("pathGo"),
    menuButton: document.getElementById("fileMenuBtn"),
    overflow: document.getElementById("fileOverflowMenu"),
    refresh: document.getElementById("fileRefresh"),
    mkdir: document.getElementById("fileNewFolder"),
    newFile: document.getElementById("fileNewFile"),
    setHome: document.getElementById("fileSetHome"),
    addBookmark: document.getElementById("fileAddBookmark"),
    swap: document.getElementById("fileSwapPanes"),
    sync: document.getElementById("fileSyncPanes"),
    paneLeft: document.getElementById("filePaneLeft"),
    paneRight: document.getElementById("filePaneRight"),
    listLeft: document.querySelector('[data-list="left"]'),
    listRight: document.querySelector('[data-list="right"]'),
    selectionBar: document.getElementById("selectionBar"),
    selectionAll: document.getElementById("selectionAll"),
    selectionInvert: document.getElementById("selectionInvert"),
    selectionExit: document.getElementById("selectionExit"),
    selectionActions: document.getElementById("selectionActions"),
    pickerBar: document.getElementById("filePickerBar"),
    pickerMessage: document.getElementById("filePickerMessage"),
    pickerCancel: document.getElementById("filePickerCancel"),
    pickerDirectory: document.getElementById("filePickerConfirmDirectory"),
    jobBar: document.getElementById("fileJobBar"),
    jobTitle: document.getElementById("fileJobTitle"),
    jobPercent: document.getElementById("fileJobPercent"),
    jobProgress: document.getElementById("fileJobProgress"),
    jobDetail: document.getElementById("fileJobDetail"),
    jobCancel: document.getElementById("fileJobCancel"),
    placesEdge: document.getElementById("filePlacesEdge"),
    placesBackdrop: document.getElementById("filePlacesBackdrop"),
    placesSheet: document.getElementById("filePlacesSheet"),
    placesHandle: document.getElementById("filePlacesHandle"),
    placesRecentTab: document.getElementById("filePlacesRecentTab"),
    placesBookmarkTab: document.getElementById("filePlacesBookmarkTab"),
    placesRecentCount: document.getElementById("filePlacesRecentCount"),
    placesBookmarkCount: document.getElementById("filePlacesBookmarkCount"),
    placesClose: document.getElementById("filePlacesClose"),
    placesList: document.getElementById("filePlacesList"),
  };

  const placeAction = {
    modal: document.getElementById("placeActionModal"),
    title: document.getElementById("placeActionTitle"),
    path: document.getElementById("placeActionPath"),
    addBookmark: document.getElementById("placeActionAddBookmark"),
    editNote: document.getElementById("placeActionEditNote"),
    delete: document.getElementById("placeActionDelete"),
    cancel: document.getElementById("placeActionCancel"),
  };

  const bookmarkNoteDialog = {
    modal: document.getElementById("bookmarkNoteModal"),
    path: document.getElementById("bookmarkNotePath"),
    input: document.getElementById("bookmarkNoteInput"),
    cancel: document.getElementById("bookmarkNoteCancel"),
    ok: document.getElementById("bookmarkNoteConfirm"),
  };

  const action = {
    modal: document.getElementById("actionModal"),
    title: document.getElementById("actionTitle"),
    target: document.getElementById("actionTarget"),
    cancel: document.getElementById("actionCancel"),
    copy: document.getElementById("actCopy"),
    move: document.getElementById("actMove"),
    compress: document.getElementById("actCompress"),
    extract: document.getElementById("actExtract"),
    installApk: document.getElementById("actInstallApk"),
    edit: document.getElementById("actEdit"),
    image: document.getElementById("actImage"),
    browse: document.getElementById("actBrowseArchive"),
    rename: document.getElementById("actRename"),
    exec: document.getElementById("actExec"),
    auto: document.getElementById("actAuto"),
    properties: document.getElementById("actProperties"),
    susfs: document.getElementById("actSusfs"),
    susfsDetails: document.getElementById("actSusfsDetails"),
    susfsTarget: document.getElementById("actSusfsTarget"),
    delete: document.getElementById("actDelete"),
  };

  const operationConfirm = {
    modal: document.getElementById("operationConfirmModal"),
    title: document.getElementById("operationConfirmTitle"),
    summary: document.getElementById("operationConfirmSummary"),
    target: document.getElementById("operationConfirmTarget"),
    conflicts: document.getElementById("operationConflictOptions"),
    cancel: document.getElementById("operationConfirmCancel"),
    ok: document.getElementById("operationConfirmOk"),
  };

  const apkInstallDialog = {
    modal: document.getElementById("apkInstallModal"),
    path: document.getElementById("apkInstallPath"),
    cancel: document.getElementById("apkInstallCancel"),
    ok: document.getElementById("apkInstallConfirm"),
  };

  const renameDialog = {
    modal: document.getElementById("renameModal"),
    title: document.getElementById("renameTitle"),
    oldName: document.getElementById("renameOldName"),
    label: document.getElementById("renameLabel"),
    input: document.getElementById("renameInput"),
    cancel: document.getElementById("renameCancel"),
    ok: document.getElementById("renameConfirm"),
  };

  const deleteDialog = {
    modal: document.getElementById("deleteModal"),
    message: document.getElementById("deleteMessage"),
    target: document.getElementById("deleteTargetName"),
    cancel: document.getElementById("deleteCancel"),
    ok: document.getElementById("deleteConfirm"),
  };

  const mkdirDialog = {
    modal: document.getElementById("mkdirModal"),
    parent: document.getElementById("mkdirParent"),
    input: document.getElementById("mkdirInput"),
    cancel: document.getElementById("mkdirCancel"),
    ok: document.getElementById("mkdirConfirm"),
  };

  const createFileDialog = {
    modal: document.getElementById("createFileModal"),
    parent: document.getElementById("createFileParent"),
    input: document.getElementById("createFileInput"),
    cancel: document.getElementById("createFileCancel"),
    ok: document.getElementById("createFileConfirm"),
  };

  const propertiesDialog = {
    modal: document.getElementById("propertiesModal"),
    path: document.getElementById("propertiesPath"),
    loading: document.getElementById("propertiesLoading"),
    content: document.getElementById("propertiesContent"),
    type: document.getElementById("propertiesType"),
    size: document.getElementById("propertiesSize"),
    mtime: document.getElementById("propertiesMtime"),
    mode: document.getElementById("propertiesMode"),
    owner: document.getElementById("propertiesOwner"),
    group: document.getElementById("propertiesGroup"),
    linkRow: document.getElementById("propertiesLinkRow"),
    link: document.getElementById("propertiesLink"),
    editMode: document.getElementById("propertiesEditMode"),
    editOwner: document.getElementById("propertiesEditOwner"),
    close: document.getElementById("propertiesClose"),
  };

  const permissionDialog = {
    modal: document.getElementById("permissionModal"),
    grid: document.getElementById("permissionGrid"),
    checkboxes: Array.from(document.querySelectorAll("#permissionModal [data-mode-bit]")),
    preview: document.getElementById("permissionPreview"),
    symlinkNote: document.getElementById("permissionSymlinkNote"),
    recursive: document.getElementById("permissionRecursive"),
    recursiveFiles: document.getElementById("permissionRecursiveFiles"),
    recursiveDirectories: document.getElementById("permissionRecursiveDirectories"),
    cancel: document.getElementById("permissionCancel"),
    ok: document.getElementById("permissionConfirm"),
  };

  const ownershipDialog = {
    modal: document.getElementById("ownershipModal"),
    user: document.getElementById("ownershipUser"),
    group: document.getElementById("ownershipGroup"),
    userList: document.getElementById("ownershipUserList"),
    groupList: document.getElementById("ownershipGroupList"),
    userCurrent: document.getElementById("ownershipUserCurrent"),
    groupCurrent: document.getElementById("ownershipGroupCurrent"),
    recursive: document.getElementById("ownershipRecursive"),
    recursiveFiles: document.getElementById("ownershipRecursiveFiles"),
    recursiveDirectories: document.getElementById("ownershipRecursiveDirectories"),
    cancel: document.getElementById("ownershipCancel"),
    ok: document.getElementById("ownershipConfirm"),
  };

  const execDialog = {
    modal: document.getElementById("execModal"),
    code: document.getElementById("execCode"),
    args: document.getElementById("argInput"),
    cancel: document.getElementById("execCancel"),
    ok: document.getElementById("execConfirm"),
  };

  const autoDialog = {
    modal: document.getElementById("autoModal"),
    code: document.getElementById("autoCode"),
    args: document.getElementById("autoArgInput"),
    cancel: document.getElementById("autoCancel"),
    ok: document.getElementById("autoConfirm"),
  };

  const quickTaskDialog = {
    modal: document.getElementById("confirmQuickTaskModal"),
    cancel: document.getElementById("confirmQuickTaskCancel"),
    ok: document.getElementById("confirmQuickTaskOk"),
  };

  const execMountDialog = {
    modal: document.getElementById("execMountModal"),
    target: document.getElementById("execMountTarget"),
    cancel: document.getElementById("execMountCancel"),
    ok: document.getElementById("execMountConfirm"),
  };

  let textEditor;
  let imageViewer;
  let archiveBrowser;

  const model = new FileManagerModel();
  const loadSequence = { left: 0, right: 0 };
  let initialized = false;
  let actionContext = null;
  let pendingOperation = null;
  let pendingApkPath = "";
  let jobPollTimer = null;
  let jobCleanupTimer = null;
  let jobPollInFlight = false, jobCancelInFlight = false, jobPollEpoch = 0, polledJobId = "";
  let jobContinuation = null;
  let pendingResume = null, workspaceLoading = null, stopped = false;
  let hideDirCache = "";
  let pendingMode = null;
  let pendingPreparedFile = null;
  let createFileSnapshot = null;
  let propertiesSession = null;
  let suppressClickUntil = 0;
  let pointerGesture = null;
  const activeTouchPointers = new Set();
  let multiTouchGesture = false;
  let placesTab = "recent";
  let placesPane = "left";
  let placeActionContext = null;
  let bookmarkNotePath = "";
  let placesSaveQueue = Promise.resolve();
  let placesPullGesture = null;
  let placesTouchGesture = null;
  let placesEdgeGesture = null;
  let placesSuppressClickUntil = 0;
  let filePicker = null;
  let pickerSequence = 0;
  let pickerRestoration = null;
  let pickerDelivery = null;

  function setIconButton(button, iconName, label, size = 20) {
    if (!button) return;
    button.innerHTML = `${icons.icon(iconName, size)}<span>${ui.safeHtml(label)}</span>`;
    button.setAttribute("aria-label", label);
  }

  function installIcons() {
    elements.close.innerHTML = icons.icon("arrow-left", 25);
    elements.menuButton.innerHTML = icons.icon("ellipsis-vertical", 27);
    elements.pathGo.innerHTML = icons.icon("move-right", 19);
    setIconButton(elements.refresh, "refresh-cw", "刷新");
    setIconButton(elements.mkdir, "folder-plus", "新建文件夹");
    setIconButton(elements.newFile, "file-plus", "新建空白文件");
    setIconButton(elements.setHome, "house", "设为首页");
    setIconButton(elements.addBookmark, "bookmark-plus", "添加书签");
    setIconButton(elements.swap, "move-right", "交换窗口");
    setIconButton(elements.sync, "columns-2", "同步窗口");
    setIconButton(elements.selectionAll, "check-square", "全选");
    setIconButton(elements.selectionInvert, "square-dashed", "反选");
    setIconButton(elements.selectionExit, "x", "退出");
    setIconButton(elements.selectionActions, "settings", "操作");
    setIconButton(action.copy, "copy", "复制");
    setIconButton(action.move, "scissors", "移动");
    setIconButton(action.compress, "archive", "压缩为 ZIP");
    setIconButton(action.extract, "archive", "解压");
    setIconButton(action.installApk, "package-plus", "安装 APK");
    setIconButton(action.edit, "pencil", "编辑");
    setIconButton(action.image, "image", "查看图片");
    setIconButton(action.browse, "folder", "浏览压缩包");
    setIconButton(action.rename, "pencil", "重命名");
    if (action.exec) action.exec.hidden = true;
    if (action.auto) action.auto.hidden = true;
    setIconButton(action.properties, "info", "属性");
    setIconButton(action.susfs, "shield", "设置规则");
    setIconButton(action.susfsDetails, "info", "查看规则");
    setIconButton(action.susfsTarget, "check", "选择为重定向目标");
    setIconButton(action.delete, "trash-2", "删除");
    setIconButton(placeAction.addBookmark, "bookmark-plus", "添加到书签");
    setIconButton(placeAction.editNote, "pencil", "修改备注");
    setIconButton(placeAction.delete, "trash-2", "删除");
    elements.placesClose.innerHTML = icons.icon("x", 22);
    setIconButton(propertiesDialog.editMode, "shield", "修改权限");
    setIconButton(propertiesDialog.editOwner, "user-round", "修改所有者/用户组");
  }

  function paneElement(pane) {
    return pane === "left" ? elements.paneLeft : elements.paneRight;
  }

  function listElement(pane) {
    return pane === "left" ? elements.listLeft : elements.listRight;
  }

  function formatBytes(value) {
    return ui.formatBytes(Number(value) || 0);
  }

  function normalizeEntry(item) {
    const type = item?.type || (item?.isDir ? "directory" : "file");
    return {
      ...item,
      type,
      isDir: type === "directory" || !!item?.isDir,
      hideProtected: item?.hideProtected === 1 || item?.hideProtected === true || item?.hideProtected === "1",
    };
  }

  function entryIcon(item) {
    if (item.parent || item.type === "directory" || item.isDir) return icons.icon("folder", 22);
    if (item.type === "symlink") return icons.icon("move-right", 20);
    if (isImageName(item.name)) return icons.icon("image", 20);
    if (isSupportedSingleArchivePath(item.name)) return icons.icon("archive", 20);
    if (/\.(?:sh|js|json|xml|ini|conf|txt|log|md|cpp|h)$/i.test(item.name || "")) return icons.icon("file-code", 20);
    return icons.icon("file", 20);
  }

  function entryMeta(item) {
    if (item.parent) return "返回上一级";
    const timestamp = item.date || item.time || "";
    const detail = item.isDir ? "文件夹" : formatBytes(item.size);
    return [detail, timestamp,
      item.duplicateIndex > 1 ? `同名条目 ${item.duplicateIndex}` : "",
      item.selectable === false ? "不支持解压" : ""].filter(Boolean).join("  ");
  }

  function rowHtml(pane, item, parent = false) {
    const path = parent ? parentPath(model.panes[pane].path) : model.entryKey(pane, item);
    const selected = model.selectionPane === pane && model.selectedPaths.has(path);
    const type = parent ? "directory" : item.type;
    return `<div class="fm-row${parent ? " parent" : ""}${selected ? " selected" : ""}${item.hideProtected ? " hidden-protected" : ""}"
      role="button" tabindex="0" aria-label="${ui.safeHtml(parent ? "返回上级目录" : item.name)}" data-pane="${pane}" data-path="${ui.safeHtml(path)}" data-name="${ui.safeHtml(item.name || "..")}" data-type="${type}" data-parent="${parent}">
      <div class="fm-file-icon">${entryIcon(parent ? { parent: true, type: "directory" } : item)}</div>
      ${item.hideProtected ? `<span class="fm-protected-mark" aria-hidden="true">${icons.icon("shield", 10)}</span>` : ""}
      <div class="fm-file-info">
        <div class="fm-file-name">${ui.safeHtml(parent ? ".." : item.name)}</div>
        <div class="fm-file-meta">${ui.safeHtml(entryMeta(parent ? { parent: true } : item))}</div>
      </div>
    </div>`;
  }

  function renderPane(pane, restoreScroll = true) {
    const state = model.panes[pane];
    const list = listElement(pane);
    if (state.loading) {
      list.innerHTML = rowHtml(pane, { name: "..", type: "directory" }, true)
        + `<div class="fm-loading">${state.archive && state.archive.phase !== "ready"
          ? `正在索引压缩包 · ${state.archive.scanned} 项<br>点上一级可取消` : "正在读取..."}</div>`;
    } else if (state.error) {
      list.innerHTML = rowHtml(pane, { name: "..", type: "directory" }, true)
        + `<div class="fm-error">${ui.safeHtml(state.error)}</div>`;
    } else {
      const rows = state.entries.map(item => rowHtml(pane, item)).join("");
      list.innerHTML = rowHtml(pane, { name: "..", type: "directory" }, true)
        + (rows || '<div class="fm-empty">空目录</div>');
      if (state.archive && state.archive.total > 500) {
        const a = state.archive;
        list.insertAdjacentHTML("beforeend", `<div class="fm-archive-pages"><button type="button" data-page="${Math.max(0, a.offset - 500)}" ${a.offset === 0 ? "disabled" : ""}>上一页</button><span>${a.offset + 1}–${Math.min(a.offset + state.entries.length, a.total)} / ${a.total}</span><button type="button" data-page="${a.offset + 500}" ${a.offset + 500 >= a.total ? "disabled" : ""}>下一页</button></div>`);
      }
    }
    decorateRuleBadges(pane);
    paneElement(pane).classList.toggle("active", model.activePane === pane);
    if (restoreScroll) requestAnimationFrame(() => { list.scrollTop = state.scrollTop || 0; });
  }

  function renderHeader() {
    const pane = model.panes[model.activePane];
    const folders = pane.entries.filter(item => item.isDir).length;
    const files = pane.entries.length - folders;
    elements.pathText.textContent = pane.archive ? `${pane.archive.archivePath}!/${pane.archive.innerPath}` : pane.path;
    elements.pathText.title = elements.pathText.textContent;
    elements.pathText.setAttribute("aria-label", `编辑当前目录路径：${elements.pathText.textContent}`);
    const selected = model.selectionPane ? `　已选: ${model.selectedPaths.size}` : "";
    elements.pathMeta.textContent = `${pane.archive ? "压缩包 · 只读　" : ""}文件夹: ${folders}　文件: ${files}${selected}`;
    for (const button of [elements.mkdir, elements.newFile, elements.setHome, elements.addBookmark, elements.sync]) {
      button.disabled = !!pane.archive;
      button.title = pane.archive ? "压缩包内仅支持浏览与解压" : "";
    }
    elements.paneLeft.classList.toggle("active", model.activePane === "left");
    elements.paneRight.classList.toggle("active", model.activePane === "right");
  }

  function decorateRuleBadges(pane) {
    const state = model.panes[pane];
    const showSusfs = canUseSusfs() && !state.archive;
    const glyphs = { path: 'eye-off', kstat: 'fingerprint', redirect: 'route', map: 'layers', mount: 'hard-drive' };
    for (const row of listElement(pane).querySelectorAll('.fm-row[data-parent="false"]')) {
      const presentation = !showSusfs ? { indicators: [], state: 'none', description: '' }
        : window.SKSusfsConsole?.filePresentation(row.dataset.path) || { indicators: [], state: 'unknown', description: 'SUSFS 状态未确认' };
      if (showSusfs) row.dataset.ruleState = presentation.state;
      else delete row.dataset.ruleState;
      const signature = JSON.stringify(presentation.indicators);
      if (row.dataset.ruleSignature !== signature) {
        row.querySelector('.fm-rule-watermarks')?.remove();
        if (presentation.indicators.length) {
          const group = document.createElement('div'); group.className = 'fm-rule-watermarks'; group.setAttribute('aria-hidden', 'true');
          for (const indicator of presentation.indicators.slice(0, 5)) {
            const icon = document.createElement('span'); icon.className = 'fm-rule-watermark';
            icon.dataset.ruleKind = indicator.kind; icon.dataset.state = indicator.state;
            icon.innerHTML = icons.icon(glyphs[indicator.kind] || 'shield', 32); group.append(icon);
          }
          row.append(group);
        }
        row.dataset.ruleSignature = signature;
      }
      if (!showSusfs) delete row.dataset.ruleSignature;
      const protectedLabel = row.classList.contains('hidden-protected') ? '隐藏保护' : '';
      row.setAttribute('aria-label', [row.dataset.name, protectedLabel, presentation.description].filter(Boolean).join('，'));
      row.title = [row.dataset.path, protectedLabel, presentation.description].filter(Boolean).join(' · ');
    }
  }

  function renderSelection() {
    const selecting = !!model.selectionPane;
    elements.selectionBar.hidden = !selecting || isJobRunning();
    elements.placesEdge.hidden = true;
    document.getElementById("selectionCount").textContent = `已选 ${model.selectedPaths.size}`;
    for (const item of document.querySelectorAll("[data-selection-only]")) item.hidden = !selecting;
    elements.selectionActions.disabled = !selecting || model.selectedPaths.size === 0 || isJobRunning();
    elements.selectionActions.querySelector("span").textContent = "操作";
    const paged = selecting && !!model.panes[model.selectionPane].archive;
    elements.selectionAll.querySelector("span").textContent = paged ? "本页全选" : "全选";
    elements.selectionInvert.querySelector("span").textContent = paged ? "本页反选" : "反选";
    renderHeader();
  }

  function renderAll() {
    renderPane("left");
    renderPane("right");
    renderSelection();
  }

  function placeDisplayName(path, note = "") {
    const label = String(note || "").trim();
    if (label) return label;
    const normalized = normalizePath(path);
    if (normalized === "/") return "/";
    return normalized.split("/").filter(Boolean).pop() || normalized;
  }

  function placesItems() {
    return placesTab === "bookmark" ? model.bookmarks : model.recent;
  }

  function renderPlaces() {
    elements.placesRecentCount.textContent = String(model.recent.length);
    elements.placesBookmarkCount.textContent = String(model.bookmarks.length);
    elements.placesRecentTab.classList.toggle("active", placesTab === "recent");
    elements.placesBookmarkTab.classList.toggle("active", placesTab === "bookmark");
    const items = placesItems();
    if (!items.length) {
      const emptyText = placesTab === "bookmark" ? "还没有书签\n可从右上角菜单添加当前目录" : "还没有最近访问的目录";
      const emptyIcon = placesTab === "bookmark" ? "bookmark" : "history";
      elements.placesList.innerHTML = `<div class="fm-place-empty">${icons.icon(emptyIcon, 34)}<span>${ui.safeHtml(emptyText).replace(/\n/g, "<br>")}</span></div>`;
      return;
    }
    elements.placesList.innerHTML = items.map(item => {
      const kind = placesTab;
      const name = placeDisplayName(item.path, item.note);
      const iconName = kind === "bookmark" ? "bookmark" : "folder";
      return `<div class="fm-place-row" data-kind="${kind}" data-path="${ui.safeHtml(item.path)}" role="button" tabindex="0">
        <div class="fm-place-icon">${icons.icon(iconName, 22)}</div>
        <div class="fm-place-info">
          <div class="fm-place-name">${ui.safeHtml(name)}</div>
          <div class="fm-place-path">${ui.safeHtml(item.path)}</div>
        </div>
      </div>`;
    }).join("");
  }

  function queuePlacesSave() {
    const snapshot = model.placesSnapshot();
    const request = placesSaveQueue.catch(() => {}).then(() => RequestApi.setFilePlaces(snapshot));
    placesSaveQueue = request;
    return request;
  }

  async function reloadPlaces() {
    const data = await RequestApi.getFilePlaces().catch(() => ({ bookmarks: [], recent: [] }));
    model.setPlaces(data?.bookmarks, data?.recent);
    renderPlaces();
  }

  function recordRecent(path) {
    if (!model.touchRecent(path)) return;
    renderPlaces();
    queuePlacesSave().catch(error => console.error("保存最近目录失败", error));
  }

  async function addBookmarkPath(path) {
    if (!model.addBookmark(path)) {
      ui.showToast("该目录已在书签中", 1500);
      return false;
    }
    renderPlaces();
    try {
      await queuePlacesSave();
      ui.showToast("已添加书签", 1500);
      return true;
    } catch (error) {
      await reloadPlaces();
      alert(error?.message || "书签保存失败");
      return false;
    }
  }

  function setPlacesTab(tab) {
    placesTab = tab === "bookmark" ? "bookmark" : "recent";
    elements.placesList.scrollTop = 0;
    renderPlaces();
  }

  function openPlaces(tab = placesTab) {
    placesPane = model.activePane;
    setPlacesTab(tab);
    elements.overflow.hidden = true;
    elements.placesSheet.style.removeProperty("transform");
    elements.placesSheet.classList.remove("dragging");
    elements.placesBackdrop.classList.add("show");
    elements.placesSheet.classList.add("show");
    elements.placesSheet.setAttribute("aria-hidden", "false");
    elements.placesEdge.hidden = true;
  }

  function closePlaces() {
    elements.placesSheet.style.removeProperty("transform");
    elements.placesSheet.classList.remove("dragging", "show");
    elements.placesBackdrop.classList.remove("show");
    elements.placesSheet.setAttribute("aria-hidden", "true");
    elements.placesEdge.hidden = !!model.selectionPane || !!model.activeJob;
    placesPullGesture = null;
    placesTouchGesture = null;
  }

  function showPlaceAction(kind, path) {
    placeActionContext = { kind, path: normalizePath(path) };
    placeAction.title.textContent = kind === "bookmark" ? "书签操作" : "最近目录操作";
    placeAction.path.textContent = placeActionContext.path;
    placeAction.addBookmark.hidden = kind === "bookmark";
    placeAction.editNote.hidden = kind !== "bookmark";
    placeAction.delete.querySelector("span").textContent = kind === "bookmark" ? "删除书签" : "删除记录";
    ui.showModal(placeAction.modal);
  }

  async function deletePlace() {
    if (!placeActionContext) return;
    const { kind, path } = placeActionContext;
    const changed = kind === "bookmark" ? model.removeBookmark(path) : model.removeRecent(path);
    ui.hideModal(placeAction.modal);
    placeActionContext = null;
    if (!changed) return;
    renderPlaces();
    try {
      await queuePlacesSave();
      ui.showToast(kind === "bookmark" ? "书签已删除" : "最近记录已删除", 1400);
    } catch (error) {
      await reloadPlaces();
      alert(error?.message || "记录保存失败");
    }
  }

  function openBookmarkNote() {
    if (placeActionContext?.kind !== "bookmark") return;
    const bookmark = model.bookmarks.find(item => item.path === placeActionContext.path);
    if (!bookmark) return;
    bookmarkNotePath = bookmark.path;
    bookmarkNoteDialog.path.textContent = bookmark.path;
    bookmarkNoteDialog.input.value = bookmark.note || "";
    placeActionContext = null;
    ui.hideModal(placeAction.modal);
    ui.showModal(bookmarkNoteDialog.modal);
  }

  async function saveBookmarkNote() {
    if (!bookmarkNotePath) return;
    const note = bookmarkNoteDialog.input.value.trim();
    if (new TextEncoder().encode(note).length > 512) {
      alert("书签备注过长，请缩短后再保存");
      return;
    }
    const changed = model.updateBookmarkNote(bookmarkNotePath, note);
    ui.hideModal(bookmarkNoteDialog.modal);
    bookmarkNotePath = "";
    if (!changed) return;
    renderPlaces();
    try {
      await queuePlacesSave();
      ui.showToast("书签备注已更新", 1400);
    } catch (error) {
      await reloadPlaces();
      alert(error?.message || "书签备注保存失败");
    }
  }

  async function navigateToPlace(path) {
    const pane = placesPane;
    closePlaces();
    model.activate(pane);
    await loadPane(pane, path, { recordRecent: true });
  }

  function attachPlacesEvents() {
    let rowGesture = null;
    elements.placesList.addEventListener("pointerdown", event => {
      const row = event.target.closest(".fm-place-row");
      if (!row || event.button > 0) return;
      rowGesture = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        moved: false,
        timer: setTimeout(() => {
          if (!rowGesture?.moved) {
            placesSuppressClickUntil = Date.now() + 600;
            showPlaceAction(row.dataset.kind, row.dataset.path);
          }
        }, 520),
      };
    });
    elements.placesList.addEventListener("pointermove", event => {
      if (!rowGesture || rowGesture.pointerId !== event.pointerId) return;
      if (Math.abs(event.clientX - rowGesture.startX) > 8 || Math.abs(event.clientY - rowGesture.startY) > 8) {
        rowGesture.moved = true;
        clearTimeout(rowGesture.timer);
      }
    });
    const finishRow = event => {
      if (!rowGesture || rowGesture.pointerId !== event.pointerId) return;
      clearTimeout(rowGesture.timer);
      rowGesture = null;
    };
    elements.placesList.addEventListener("pointerup", finishRow);
    elements.placesList.addEventListener("pointercancel", finishRow);
    elements.placesList.addEventListener("click", event => {
      if (Date.now() < placesSuppressClickUntil) return;
      const row = event.target.closest(".fm-place-row");
      if (row) navigateToPlace(row.dataset.path);
    });
    elements.placesList.addEventListener("keydown", event => {
      if (event.key !== "Enter" && event.key !== " ") return;
      const row = event.target.closest(".fm-place-row");
      if (!row) return;
      event.preventDefault();
      navigateToPlace(row.dataset.path);
    });
    elements.placesList.addEventListener("contextmenu", event => {
      const row = event.target.closest(".fm-place-row");
      if (!row) return;
      event.preventDefault();
      showPlaceAction(row.dataset.kind, row.dataset.path);
    });

    elements.placesSheet.addEventListener("pointerdown", event => {
      const fromHandle = !!event.target.closest("#filePlacesHandle");
      const fromListTop = !!event.target.closest("#filePlacesList") && elements.placesList.scrollTop <= 0;
      if ((!fromHandle && !fromListTop) || event.button > 0) return;
      placesPullGesture = { pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, distance: 0, captured: fromHandle };
      if (fromHandle) elements.placesSheet.setPointerCapture?.(event.pointerId);
    });
    elements.placesSheet.addEventListener("pointermove", event => {
      if (!placesPullGesture || placesPullGesture.pointerId !== event.pointerId) return;
      const dx = event.clientX - placesPullGesture.startX;
      const dy = event.clientY - placesPullGesture.startY;
      if (dy <= 0 || Math.abs(dy) <= Math.abs(dx)) return;
      event.preventDefault();
      placesPullGesture.distance = Math.min(dy, window.innerHeight * .55);
      elements.placesSheet.classList.add("dragging");
      elements.placesSheet.style.transform = `translateY(${placesPullGesture.distance}px)`;
    }, { passive: false });
    const finishPull = event => {
      if (!placesPullGesture || placesPullGesture.pointerId !== event.pointerId) return;
      const dismiss = placesPullGesture.distance >= 72;
      if (placesPullGesture.captured && elements.placesSheet.hasPointerCapture?.(event.pointerId)) {
        elements.placesSheet.releasePointerCapture?.(event.pointerId);
      }
      placesPullGesture = null;
      elements.placesSheet.style.removeProperty("transform");
      elements.placesSheet.classList.remove("dragging");
      if (dismiss) closePlaces();
    };
    elements.placesSheet.addEventListener("pointerup", finishPull);
    elements.placesSheet.addEventListener("pointercancel", finishPull);

    // Android WebView may hand vertical pointer gestures to native scrolling
    // before pointermove can be cancelled. A non-passive touch fallback keeps
    // pull-down-to-dismiss reliable when the list is already at its top.
    elements.placesList.addEventListener("touchstart", event => {
      if (event.touches.length !== 1 || elements.placesList.scrollTop > 0) return;
      const touch = event.touches[0];
      placesTouchGesture = { startX: touch.clientX, startY: touch.clientY, distance: 0 };
    }, { passive: true });
    elements.placesList.addEventListener("touchmove", event => {
      if (!placesTouchGesture || event.touches.length !== 1) return;
      const touch = event.touches[0];
      const dx = touch.clientX - placesTouchGesture.startX;
      const dy = touch.clientY - placesTouchGesture.startY;
      if (dy <= 0 || Math.abs(dy) <= Math.abs(dx)) return;
      event.preventDefault();
      placesTouchGesture.distance = Math.min(dy, window.innerHeight * .55);
      elements.placesSheet.classList.add("dragging");
      elements.placesSheet.style.transform = `translateY(${placesTouchGesture.distance}px)`;
    }, { passive: false });
    const finishTouchPull = () => {
      if (!placesTouchGesture) return;
      const dismiss = placesTouchGesture.distance >= 72;
      placesTouchGesture = null;
      elements.placesSheet.style.removeProperty("transform");
      elements.placesSheet.classList.remove("dragging");
      if (dismiss) closePlaces();
    };
    elements.placesList.addEventListener("touchend", finishTouchPull);
    elements.placesList.addEventListener("touchcancel", finishTouchPull);

    elements.placesEdge.addEventListener("pointerdown", event => {
      if (event.button > 0) return;
      placesEdgeGesture = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        moved: false,
        opened: false,
      };
      elements.placesEdge.setPointerCapture?.(event.pointerId);
    });
    elements.placesEdge.addEventListener("pointermove", event => {
      if (!placesEdgeGesture || placesEdgeGesture.pointerId !== event.pointerId) return;
      const dx = event.clientX - placesEdgeGesture.startX;
      const dy = event.clientY - placesEdgeGesture.startY;
      const upward = -dy;
      if (Math.abs(dx) > 8 || Math.abs(dy) > 8) placesEdgeGesture.moved = true;
      if (upward > 0 && upward > Math.abs(dx)) event.preventDefault();
      if (upward >= 32 && upward > Math.abs(dx) * 1.2) {
        placesEdgeGesture.opened = true;
        openPlaces();
      }
    });
    const finishEdge = event => {
      if (!placesEdgeGesture || placesEdgeGesture.pointerId !== event.pointerId) return;
      const shouldOpenAsTap = !placesEdgeGesture.opened && !placesEdgeGesture.moved;
      placesEdgeGesture = null;
      if (shouldOpenAsTap) openPlaces();
    };
    elements.placesEdge.addEventListener("pointerup", finishEdge);
    elements.placesEdge.addEventListener("pointercancel", () => { placesEdgeGesture = null; });
  }

  function activatePane(pane) {
    model.activate(pane);
    renderHeader();
  }

  async function loadPane(pane, requestedPath, options = {}) {
    const sequence = ++loadSequence[pane];
    await archiveBrowser?.leave(pane);
    if (sequence !== loadSequence[pane]) return;
    const list = listElement(pane);
    model.panes[pane].scrollTop = list.scrollTop;
    const path = model.navigate(pane, requestedPath);
    model.panes[pane].loading = true;
    model.panes[pane].error = "";
    if (options.activate !== false) activatePane(pane);
    renderPane(pane, false);
    renderSelection();
    try {
      const items = await RequestApi.listDir(path);
      if (sequence !== loadSequence[pane]) return;
      model.setEntries(pane, items.map(normalizeEntry));
      model.panes[pane].loading = false;
      model.panes[pane].scrollTop = 0;
      if (options.recordRecent === true && !filePicker) recordRecent(path);
    } catch (error) {
      if (sequence !== loadSequence[pane]) return;
      model.panes[pane].loading = false;
      model.panes[pane].error = error?.message || "无法读取目录";
      model.setEntries(pane, []);
    }
    renderPane(pane, false);
    renderSelection();
    if (canUseSusfs()) window.SKSusfsConsole?.viewChanged();
  }

  async function refreshPane(pane) {
    const state = model.panes[pane], archive = state.archive;
    if (archive && archive.phase !== "ready") return;
    if (archive) return archiveBrowser.page(pane, archive.offset);
    const scroll = window.SKAppShell.activeView === 'files' ? listElement(pane).scrollTop : state.scrollTop;
    const selection = model.selectionPane === pane ? new Set(model.selectedPaths) : null;
    const path = state.path, request = loadSequence[pane] + 1;
    await loadPane(pane, path, { activate: false });
    if (loadSequence[pane] !== request || state.path !== path) return;
    state.scrollTop = scroll;
    if (selection && (!model.selectionPane || model.selectionPane === pane)) {
      model.selectionPane = pane;
      model.selectedPaths = new Set(state.entries.map(item => model.entryKey(pane, item)).filter(key => selection.has(key)));
    }
    renderPane(pane); renderSelection();
  }

  async function initializeWorkspace() {
    if (initialized) return;
    const [settings, places] = await Promise.all([
      RequestApi.getFileSettings().catch(() => ({ leftHome: "/sdcard", rightHome: "/sdcard" })),
      RequestApi.getFilePlaces().catch(() => ({ bookmarks: [], recent: [] })),
    ]);
    model.setHomes(settings?.leftHome || "/sdcard", settings?.rightHome || "/sdcard");
    model.setPlaces(places?.bookmarks, places?.recent);
    renderPlaces();
    model.navigate("left", model.panes.left.home);
    model.navigate("right", model.panes.right.home);
    initialized = true;
    await Promise.all([
      loadPane("left", model.panes.left.path, { activate: false, recordRecent: true }),
      loadPane("right", model.panes.right.path, { activate: false, recordRecent: true }),
    ]);
    activatePane("left");
    await resumeCurrentJob();
  }

  async function activateWorkspace(context = {}) {
    stopped = false;
    if (!initialized) {
      if (!workspaceLoading) workspaceLoading = initializeWorkspace().finally(() => { workspaceLoading = null; });
      try { await workspaceLoading; } catch (error) { ui.showToast(error?.message || '文件管理初始化失败', 2200); }
      renderAll();
    } else {
      renderHeader(); renderSelection();
      requestAnimationFrame(() => { elements.listLeft.scrollTop = model.panes.left.scrollTop || 0; elements.listRight.scrollTop = model.panes.right.scrollTop || 0; });
    }
    startJobPolling();
    if (context.from !== 'files' && canUseSusfs()) window.SKSusfsConsole?.viewChanged();
  }
  function deactivateWorkspace() {
    model.panes.left.scrollTop = elements.listLeft.scrollTop; model.panes.right.scrollTop = elements.listRight.scrollTop;
    elements.overflow.hidden = true; closePathEditor(); closePlaces();
    cancelPointerGesture();
    activeTouchPointers.clear();
    multiTouchGesture = false;
  }
  function openWorkspace() { return window.SKAppShell.navigate('files'); }
  function backInWorkspace() {
    if (!elements.overflow.hidden) { elements.overflow.hidden = true; return true; }
    if (!elements.pathEditor.hidden) { closePathEditor(); return true; }
    if (filePicker) { finishFilePicker({ cancelled: true, reason: 'cancel' }); return true; }
    if (model.selectionPane) { model.clearSelection(); renderAll(); return true; }
    return false;
  }

  function refreshRestoredPickerPane(pane, state) {
    const sequence = loadSequence[pane], scroll = state.scrollTop;
    if (state.archive) {
      void archiveBrowser.resume(pane).then(() => {
        if (model.panes[pane] !== state || loadSequence[pane] !== sequence) return;
        state.scrollTop = scroll;
        trimPickerSelection(pane);
        renderPane(pane); renderSelection();
      });
      return;
    }
    void RequestApi.listDir(state.path).then(items => {
      if (model.panes[pane] !== state || loadSequence[pane] !== sequence) return;
      state.entries = items.map(normalizeEntry); state.loading = false; state.error = '';
      trimPickerSelection(pane);
      renderPane(pane); renderSelection();
    }).catch(() => {});
  }

  function trimPickerSelection(pane) {
    if (model.selectionPane !== pane) return;
    // Archive selections span pages; absence from this page is not deletion.
    if (model.panes[pane].archive) {
      if (model.panes[pane].error) model.clearSelection();
      return;
    }
    const existing = new Set(model.panes[pane].entries.map(item => model.entryKey(pane, item)));
    model.selectedPaths = new Set([...model.selectedPaths].filter(path => existing.has(path)));
    model.selectedArchiveItems = new Map([...model.selectedArchiveItems].filter(([path]) => existing.has(path)));
  }

  function finishFilePicker(result) {
    const session = filePicker;
    if (!session) return pickerRestoration || Promise.resolve(false);
    filePicker = null;
    ++pickerSequence;
    cancelPointerGesture();
    for (const pane of ['left', 'right']) ++loadSequence[pane];
    elements.pickerBar.hidden = true;
    elements.pickerDirectory.hidden = true;
    elements.workspace.removeAttribute('data-picking-file');
    elements.menuButton.disabled = false;
    if (session.snapshot) {
      const old = session.snapshot;
      model.panes = old.panes; model.activePane = old.activePane;
      model.selectionPane = old.selectionPane;
      model.selectedPaths = old.selectedPaths;
      model.selectedArchiveItems = old.selectedArchiveItems;
      for (const pane of ['left', 'right']) {
        model.panes[pane].loading = false;
        model.panes[pane].scrollTop = old.scrollTop[pane];
      }
      renderAll();
      for (const pane of ['left', 'right']) refreshRestoredPickerPane(pane, model.panes[pane]);
    }
    const restoredPanes = model.panes;
    const delivery = pickerDelivery = { result, delivered: false };
    const restoring = new Promise(resolve => requestAnimationFrame(() => {
      if (model.panes === restoredPanes && session.snapshot) {
        for (const pane of ['left', 'right']) {
          restoredPanes[pane].scrollTop = session.snapshot.scrollTop[pane];
          listElement(pane).scrollTop = session.snapshot.scrollTop[pane];
        }
      }
      delivery.delivered = true;
      session.resolve(delivery.result);
      resolve(true);
    }));
    pickerRestoration = restoring;
    void restoring.then(() => {
      if (pickerRestoration === restoring) pickerRestoration = null;
      if (pickerDelivery === delivery) pickerDelivery = null;
    });
    return restoring;
  }

  async function prepareFilePicker(session, initialPath) {
    const navigated = await window.SKAppShell.navigate('files');
    if (filePicker !== session) return;
    if (!navigated || window.SKAppShell.activeView !== 'files') {
      finishFilePicker({ cancelled: true, reason: 'navigation' }); return;
    }
    // activateWorkspace restores hidden panes in its next animation frame.
    // Capture afterwards so an automation round trip does not replace their
    // saved scroll positions with the hidden DOM's zero offsets.
    await new Promise(resolve => requestAnimationFrame(resolve));
    if (filePicker !== session || window.SKAppShell.activeView !== 'files') return;
    for (const pane of ['left', 'right']) {
      model.panes[pane].scrollTop = listElement(pane).scrollTop;
      ++loadSequence[pane];
    }
    session.snapshot = { panes: model.panes, activePane: model.activePane,
      selectionPane: model.selectionPane, selectedPaths: new Set(model.selectedPaths),
      selectedArchiveItems: new Map(model.selectedArchiveItems),
      scrollTop: Object.fromEntries(['left', 'right'].map(pane => [pane, model.panes[pane].scrollTop])) };
    const old = session.snapshot;
    model.panes = Object.fromEntries(['left', 'right'].map(pane => [pane, {
      ...old.panes[pane], archive: null, entries: [], loading: false, error: '', scrollTop: 0,
    }]));
    model.clearSelection();
    elements.workspace.setAttribute('data-picking-file', 'true');
    elements.pickerBar.hidden = false; elements.menuButton.disabled = true;
    elements.pickerMessage.textContent = session.purpose === 'susfs-config-export' ? '选择配置导出目录，然后点击“选择当前目录”' :
      session.purpose === 'susfs-config-import' ? '选择 JSON 配置文件，文件夹可继续浏览' :
      '选择脚本：单击文件即可使用，文件夹可继续浏览';
    elements.pickerDirectory.hidden = session.purpose !== 'susfs-config-export';
    elements.overflow.hidden = true; closePlaces(); closePathEditor();
    actionContext = null; ui.hideModal(action.modal);
    const activePane = old.activePane;
    await Promise.all(['left', 'right'].map(pane => loadPane(pane, old.panes[pane].path, { activate: false })));
    if (filePicker !== session) return;
    if (typeof initialPath === 'string' && initialPath.startsWith('/') && !initialPath.includes('\0')) {
      const parent = session.purpose === 'susfs-config-export' ? initialPath : parentPath(initialPath);
      if (parent !== model.panes[activePane].path) {
        await loadPane(activePane, parent, { activate: false });
        if (filePicker !== session) return;
        if (model.panes[activePane].error) await loadPane(activePane, old.panes[activePane].path, { activate: false });
      }
    }
    if (filePicker !== session) return;
    session.preparing = false;
    activatePane(activePane); renderAll();
  }

  function pickFile({ purpose, initialPath = '' } = {}) {
    if (!['automation-script','susfs-config-import','susfs-config-export'].includes(purpose)) return Promise.reject(new Error('不支持的文件选择用途'));
    if (filePicker || pickerRestoration || window.SKSusfsConsole?.isPicking()) return Promise.reject(new Error('请先完成当前文件选择'));
    if (window.SKAppShell.activeView === 'files' && !elements.workspace.hidden) {
      for (const pane of ['left', 'right']) model.panes[pane].scrollTop = listElement(pane).scrollTop;
    }
    return new Promise((resolve, reject) => {
      const session = filePicker = { id: ++pickerSequence, purpose, resolve, preparing: true, choosing: false, snapshot: null };
      void prepareFilePicker(session, initialPath).catch(error => {
        if (filePicker !== session) return;
        finishFilePicker({ cancelled: true, reason: 'cancel' });
        ui.showToast(error?.message || '无法打开文件选择', 2400);
      });
    });
  }

  async function choosePickerFile(item) {
    const session = filePicker;
    if (!session || session.preparing || session.choosing) return;
    if (session.purpose === 'susfs-config-export') { ui.showToast('请浏览目标文件夹后选择当前目录', 1800); return; }
    if (session.purpose === 'susfs-config-import' && !/\.json$/i.test(item.name || item.path)) { ui.showToast('请选择 JSON 配置文件', 1800); return; }
    if (item.archive || item.type !== 'file') { ui.showToast('请选择实际的普通文件', 1800); return; }
    session.choosing = true;
    elements.pickerMessage.textContent = '正在确认所选文件…';
    try {
      const properties = await RequestApi.getFileProperties(item.path);
      if (filePicker !== session) return;
      if (properties.type !== 'file' || properties.path !== item.path) throw new Error('文件已改变，请重新选择');
      finishFilePicker({ path: item.path, pane: item.pane });
    } catch (error) {
      if (filePicker === session) {
        session.choosing = false;
        elements.pickerMessage.textContent = '选择脚本：单击文件即可使用，文件夹可继续浏览';
        ui.showToast(error?.message || '文件已不存在，请重新选择', 2400);
      }
    }
  }

  async function beforeLeaveWorkspace({ to, scriptFileReturn }) {
    if (filePicker && to !== 'files') await finishFilePicker({ cancelled: true, reason: 'navigation' });
    else if (pickerRestoration) {
      if (to !== 'files' && !scriptFileReturn && pickerDelivery && !pickerDelivery.delivered) {
        pickerDelivery.result = { cancelled: true, reason: 'navigation' };
      }
      await pickerRestoration;
    }
    return true;
  }

  async function closeEditor(force = false) {
    return textEditor ? textEditor.close(force) : true;
  }

  async function closeWorkspace() {
    stopped = true;
    clearTimeout(jobCleanupTimer);
    ++jobPollEpoch;
    const force = document.visibilityState === "hidden";
    if (!(await closeEditor(force))) return;
    imageViewer?.close();
    await archiveBrowser.close();
    ++loadSequence.left;
    ++loadSequence.right;
    fileBtn?.classList.remove("active");
    elements.workspace.classList.remove("show");
    elements.workspace.setAttribute("aria-hidden", "true");
    elements.overflow.hidden = true;
    closePlaces();
    clearTimeout(jobPollTimer);
    jobPollTimer = null;
  }

  function itemFromRow(row) {
    const pane = row.dataset.pane;
    const name = row.dataset.name;
    const archive = model.panes[pane].archive;
    const entry = model.panes[pane].entries.find(item => archive ? item.id === row.dataset.path : String(item.name) === name);
    if (!entry) return null;
    return { ...entry, pane, path: archive ? entry.id : normalizePath(row.dataset.path || joinPath(model.panes[pane].path, name)),
      innerPath: archive ? entry.path : undefined, archive: !!archive };
  }

  function isImageName(name) { return /\.(?:png|jpe?g|gif|webp|bmp)$/i.test(String(name || "")); }

  function isInstallableApkName(name) {
    return /\.apk(?:\.1)?$/i.test(String(name || ""));
  }

  function showActionMenu(context) {
    if (filePicker) return;
    if (!context?.paths?.length) return;
    actionContext = context;
    const batch = context.kind === "batch";
    const item = context.items?.[0];
    const isFile = !batch && item?.type === "file";
    const canCompress = Array.isArray(context.items) && context.items.length === context.paths.length
      && context.items.every(value => ["file", "directory", "symlink"].includes(value?.type));
    const isApk = isFile && isInstallableApkName(item?.name);
    const inArchive = !!model.panes[context.pane].archive;
    action.title.textContent = batch ? `已选择 ${context.paths.length} 个项目` : (item?.isDir ? "文件夹操作" : "文件操作");
    const display = inArchive ? context.items.map(value => value.innerPath || value.path || value.name) : context.paths;
    action.target.textContent = display.slice(0, 3).join("\n") + (display.length > 3 ? `\n等 ${display.length} 项` : "");
    action.copy.hidden = action.move.hidden = action.delete.hidden = inArchive;
    action.edit.hidden = !isFile || inArchive;
    action.image.hidden = !isFile || inArchive || !isImageName(item?.name);
    action.browse.hidden = !isFile || inArchive || !isSupportedSingleArchivePath(item?.name);
    action.compress.hidden = !canCompress || inArchive;
    action.extract.hidden = inArchive ? !context.items.some(value => value.selectable !== false) : !(isFile && isSupportedSingleArchivePath(item.name));
    action.extract.disabled = !!model.panes[model.otherPane(context.pane)].archive;
    action.extract.title = action.extract.disabled ? "请将另一栏切换到实际目标目录" : "";
    action.installApk.hidden = !isApk || inArchive;
    if (action.exec) action.exec.hidden = true;
    if (action.auto) action.auto.hidden = true;
    action.rename.hidden = batch || inArchive;
    action.properties.hidden = batch || inArchive;
    updateSusfsActions();
    ui.showModal(action.modal);
  }

  function updateSusfsActions() {
    const context = actionContext;
    const blocked = !canUseSusfs() || !context || !!model.panes[context.pane].archive;
    const items = context?.items || [];
    const isFile = context?.kind !== 'batch' && items[0]?.type === 'file';
    action.susfs.hidden = blocked || !window.ObjectPolicy?.allowedKinds(items).length;
    action.susfsTarget.hidden = blocked || !isFile || !window.SKSusfsConsole?.isPicking();
    action.susfsDetails.hidden = blocked || items.length !== 1;
  }

  function isSupportedSingleArchivePath(name) {
    const value = String(name || "").toLowerCase();
    if (value.endsWith(".zip") || value.endsWith(".7z")) return true;
    if (!value.endsWith(".rar")) return false;
    const stem = value.slice(0, -4);
    const match = stem.match(/\.part(\d+)$/);
    return !match;
  }

  function showSingleAction(item) {
    showActionMenu({ kind: "single", pane: item.pane, paths: [item.path], items: [item] });
  }

  function showBatchAction() {
    // A failed batch entry must never leave a previous single-file menu usable.
    actionContext = null;
    const context = selectionContext();
    if (!context || isJobRunning()) {
      ui.hideModal(action.modal);
      return false;
    }
    showActionMenu(context);
    return true;
  }

  function selectionContext() {
    const pane = model.selectionPane;
    if (!pane || !model.selectedPaths.size) return null;
    const archive = !!model.panes[pane].archive;
    const items = model.selectedEntries().filter(item => item.selectable !== false).map(item => ({
      ...item, pane, path: model.entryKey(pane, item),
      innerPath: archive ? item.path : undefined, archive,
    }));
    if (!items.length || items.length !== model.selectedPaths.size) return null;
    return { kind: "batch", pane, paths: items.map(item => item.path), items };
  }

  function currentActionContext() {
    if (!actionContext?.paths?.length) return null;
    if (actionContext.kind === "batch") {
      const current = selectionContext();
      if (!current || current.pane !== actionContext.pane || current.paths.length !== actionContext.paths.length
          || current.paths.some(path => !actionContext.paths.includes(path))) {
        actionContext = null;
        ui.hideModal(action.modal);
        return null;
      }
    }
    return actionContext;
  }

  function beginSwipeSelection(pane, path) {
    if (filePicker) return;
    const item = model.panes[pane].entries.find(item => model.entryKey(pane, item) === path);
    if (!item || item.selectable === false || model.selectionPane && model.selectionPane !== pane) return;
    actionContext = null;
    if (!model.selectionPane) model.beginSelection(pane, path);
    else if (model.selectionPane === pane && !model.selectedPaths.has(path) && !model.toggleSelection(pane, path)) ui.showToast("一次最多选择 500 项", 1800);
    renderPane(pane, false);
    renderSelection();
  }

  function openRowAction(item) {
    if (filePicker) return;
    if (model.selectionPane !== item.pane) {
      showSingleAction(item);
      return;
    }
    if (item.selectable === false) return;
    if (!model.selectedPaths.has(item.path) && !model.toggleSelection(item.pane, item.path)) {
      ui.showToast("一次最多选择 500 项", 1800);
      return;
    }
    renderPane(item.pane, false);
    renderSelection();
    showBatchAction();
  }

  function cancelPointerGesture() {
    if (!pointerGesture) return;
    clearTimeout(pointerGesture.longPress);
    pointerGesture.row.style.removeProperty("--swipe-x");
    pointerGesture = null;
  }

  // Track touches across both panes (and outside them), so a second finger
  // cancels selection instead of replacing the first finger's gesture.
  document.addEventListener("pointerdown", event => {
    if (event.pointerType !== "touch") return;
    activeTouchPointers.add(event.pointerId);
    if (activeTouchPointers.size > 1) {
      multiTouchGesture = true;
      suppressClickUntil = Date.now() + 600;
      cancelPointerGesture();
    }
  }, true);
  for (const type of ["pointerup", "pointercancel"]) {
    document.addEventListener(type, event => {
      if (event.pointerType !== "touch") return;
      if (multiTouchGesture) suppressClickUntil = Date.now() + 600;
      activeTouchPointers.delete(event.pointerId);
      if (!activeTouchPointers.size) multiTouchGesture = false;
    }, true);
  }
  document.addEventListener("pointermove", event => {
    const gesture = pointerGesture;
    if (!gesture || gesture.pointerId !== event.pointerId || gesture.longPressed) return;
    const dx = event.clientX - gesture.startX;
    const dy = event.clientY - gesture.startY;
    if (Math.abs(dx) > 8 || Math.abs(dy) > 8) {
      gesture.moved = true;
      clearTimeout(gesture.longPress);
      if (!gesture.axis) gesture.axis = dx > 0 && dx > Math.abs(dy) * 1.35 ? "horizontal" : "vertical";
    }
    if (gesture.axis === "horizontal" && dx > 0 && dx > Math.abs(dy) * 1.35) {
      event.preventDefault();
      gesture.row.style.setProperty("--swipe-x", `${Math.min(dx, 72)}px`);
    } else {
      if (gesture.moved) gesture.axis = "vertical";
      gesture.row.style.removeProperty("--swipe-x");
    }
  }, { passive: false });
  document.addEventListener("pointerup", event => {
    const gesture = pointerGesture;
    if (!gesture || gesture.pointerId !== event.pointerId) return;
    const dx = event.clientX - gesture.startX;
    const dy = event.clientY - gesture.startY;
    const selected = !filePicker && !multiTouchGesture && !gesture.longPressed && gesture.axis !== "vertical"
      && dx >= 44 && dx > Math.abs(dy) * 1.35;
    cancelPointerGesture();
    if (gesture.moved || gesture.longPressed || selected) suppressClickUntil = Date.now() + 600;
    if (selected) beginSwipeSelection(gesture.pane, gesture.row.dataset.path);
  });
  document.addEventListener("pointercancel", event => {
    if (!pointerGesture || pointerGesture.pointerId !== event.pointerId) return;
    suppressClickUntil = Date.now() + 600;
    cancelPointerGesture();
  });
  window.addEventListener("blur", () => {
    cancelPointerGesture();
    activeTouchPointers.clear();
    multiTouchGesture = false;
  });

  function attachListEvents(pane) {
    const list = listElement(pane);
    list.addEventListener("scroll", () => {
      if (window.SKAppShell.activeView !== 'files' || elements.workspace.hidden || pickerRestoration || filePicker?.preparing) return;
      model.panes[pane].scrollTop = list.scrollTop;
    }, { passive: true });
    list.addEventListener("pointerdown", event => {
      const row = event.target.closest(".fm-row");
      if (!row || row.dataset.parent === "true" || event.button !== 0 || multiTouchGesture) return;
      cancelPointerGesture();
      activatePane(pane);
      const gesture = pointerGesture = {
        pointerId: event.pointerId,
        pointerType: event.pointerType,
        pane,
        row,
        startX: event.clientX,
        startY: event.clientY,
        moved: false,
        axis: null,
        longPressed: false,
        longPress: setTimeout(() => {
          if (pointerGesture !== gesture || gesture.moved || multiTouchGesture) return;
          gesture.longPressed = true;
          suppressClickUntil = Date.now() + 800;
          if (filePicker) return;
          const item = itemFromRow(row);
          if (item) openRowAction(item);
        }, 520),
      };
    });
    list.addEventListener("click", event => {
      if (Date.now() < suppressClickUntil) return;
      const pageButton = event.target.closest("[data-page]");
      if (pageButton && !pageButton.disabled) { archiveBrowser.page(pane, Number(pageButton.dataset.page)); return; }
      const row = event.target.closest(".fm-row");
      if (!row) return;
      activatePane(pane);
      if (row.dataset.parent === "true") {
        const archive = model.panes[pane].archive;
        if (archive?.innerPath && archive.phase === "ready") {
          archiveBrowser.navigate(pane, archive.innerPath.split("/").slice(0, -1).join("/"));
          return;
        }
        if (archive) { loadPane(pane, model.panes[pane].path); return; }
        loadPane(pane, parentPath(model.panes[pane].path), { recordRecent: true });
        return;
      }
      const item = itemFromRow(row);
      if (!item) return;
      if (filePicker) {
        if (item.isDir && !item.archive) loadPane(pane, item.path);
        else void choosePickerFile(item);
        return;
      }
      if (model.selectionPane) {
        if (model.selectionPane === pane) {
          if (item.selectable === false) return;
          if (!model.toggleSelection(pane, item.path)) ui.showToast("一次最多选择 500 项", 1800);
          renderPane(pane, false);
          renderSelection();
        } else if (item.isDir) {
          if (item.archive) archiveBrowser.navigate(pane, item.innerPath);
          else loadPane(pane, item.path, { recordRecent: true });
        }
        return;
      }
      if (item.archive && item.isDir) archiveBrowser.navigate(pane, item.innerPath);
      else if (item.isDir) loadPane(pane, item.path, { recordRecent: true });
      else showSingleAction(item);
    });
    list.addEventListener("contextmenu", event => {
      const row = event.target.closest(".fm-row");
      if (!row || row.dataset.parent === "true") return;
      event.preventDefault();
      if (filePicker) return;
      if (pointerGesture?.row === row) {
        if (pointerGesture.pointerType === "touch" || pointerGesture.longPressed) return;
        cancelPointerGesture();
        suppressClickUntil = Date.now() + 800;
      }
      const item = itemFromRow(row);
      if (item) openRowAction(item);
    });
  }

  for (const list of [elements.listLeft, elements.listRight]) list.addEventListener('keydown', event => {
    const row = event.target.closest('.fm-row');
    if (!row || event.target !== row) return;
    if (event.key === 'Enter') { event.preventDefault(); row.click(); }
    if (event.key === ' ' && row.dataset.parent !== 'true') { event.preventDefault(); if (!filePicker) beginSwipeSelection(row.dataset.pane, row.dataset.path); }
  });

  function validateName(value, label = "名称") {
    const name = String(value || "").trim();
    if (!name) throw new Error(`${label}不能为空`);
    if (name.includes("/")) throw new Error(`${label}不能包含 /`);
    if (name === "." || name === "..") throw new Error(`${label}不能是 . 或 ..`);
    if (name.includes("\0")) throw new Error(`${label}包含无效字符`);
    return name;
  }

  function validateFileName(value) {
    const name = String(value ?? "");
    if (!name || !name.trim()) throw new Error("文件名不能为空");
    if (name.includes("/")) throw new Error("文件名不能包含 /");
    if (name === "." || name === "..") throw new Error("文件名不能是 . 或 ..");
    if (name.includes("\0")) throw new Error("文件名包含无效字符");
    return name;
  }

  function operationFromContext(operation) {
    const context = currentActionContext();
    if (!context) return null;
    const sourcePane = context.pane;
    const destinationPane = model.otherPane(sourcePane);
    if (model.panes[destinationPane].archive) {
      alert("请将另一栏切换到实际目标目录");
      return null;
    }
    const archive = model.panes[sourcePane].archive;
    if (archive) {
      if (operation !== "extract" || archive.phase !== "ready") return null;
      const selected = context.items.filter(item => item.selectable !== false);
      if (!selected.length) return null;
      return { operation, sourcePane, destinationPane, sources: [archive.archivePath],
        destination: model.panes[destinationPane].path,
        archiveSelection: { sessionId: archive.sessionId, basePath: archive.innerPath, entryIds: selected.map(item => item.id) },
        selectedNames: selected.map(item => item.name) };
    }
    return {
      operation,
      sourcePane,
      destinationPane,
      sources: context.paths.slice().sort(),
      destination: model.panes[destinationPane].path,
    };
  }

  function openOperationConfirm(operation) {
    pendingOperation = null;
    const snapshot = operationFromContext(operation);
    if (!snapshot) return;
    pendingOperation = snapshot;
    ui.hideModal(action.modal);
    const operationName = operation === "copy" ? "复制"
      : operation === "move" ? "移动"
      : operation === "compress" ? "压缩"
      : "解压";
    operationConfirm.title.textContent = `确认${operationName}`;
    if (operation === "compress") {
      snapshot.defaultOutputName = defaultZipName(snapshot.sources);
      operationConfirm.summary.textContent = `将 ${snapshot.sources.length} 个项目压缩为 ZIP；同名时自动生成 (1)、(2)…`;
      operationConfirm.target.textContent = `${snapshot.destination}/${snapshot.defaultOutputName}`.replace(/\/+/g, "/");
      operationConfirm.conflicts.hidden = true;
    } else if (snapshot.archiveSelection) {
      operationConfirm.summary.textContent = `解压所选 ${snapshot.archiveSelection.entryIds.length} 项，路径相对于当前包内目录`;
      operationConfirm.target.textContent = `${snapshot.destination}\n` + snapshot.selectedNames.slice(0, 3).map(name => `→ ${joinPath(snapshot.destination, name)}`).join("\n");
      operationConfirm.conflicts.hidden = false;
    } else {
      operationConfirm.summary.textContent = `${operationName} ${snapshot.sources.length} 个项目到另一栏当前目录`;
      operationConfirm.target.textContent = snapshot.destination;
      operationConfirm.conflicts.hidden = false;
    }
    const overwrite = operationConfirm.modal.querySelector('input[value="overwrite"]');
    if (overwrite) overwrite.checked = true;
    ui.showModal(operationConfirm.modal);
  }

  async function startPendingOperation() {
    if (!pendingOperation?.sources?.length) return;
    operationConfirm.ok.disabled = true;
    try {
      const conflict = pendingOperation.operation === "compress" ? "skip"
        : operationConfirm.modal.querySelector('input[name="conflictPolicy"]:checked')?.value || "overwrite";
      const job = await RequestApi.startFileJob({
        op: pendingOperation.operation,
        sources: pendingOperation.sources,
        destination: pendingOperation.destination,
        conflict,
        ...(pendingOperation.archiveSelection ? { archiveSelection: pendingOperation.archiveSelection } : {}),
      });
      model.activeJob = job;
      model.clearSelection();
      ui.hideModal(operationConfirm.modal);
      operationConfirm.conflicts.hidden = false;
      pendingOperation = null;
      renderAll();
      updateJobBar(job);
      startJobPolling();
    } catch (error) {
      alert(error?.message || "无法启动文件任务");
    } finally {
      operationConfirm.ok.disabled = false;
    }
  }

  function openApkInstallConfirm() {
    if (actionContext?.kind !== "single" || actionContext.items?.[0]?.type !== "file"
        || !isInstallableApkName(actionContext.items[0].name)) return;
    pendingApkPath = actionContext.paths[0];
    apkInstallDialog.path.textContent = pendingApkPath;
    ui.hideModal(action.modal);
    ui.showModal(apkInstallDialog.modal);
  }

  async function confirmApkInstall() {
    if (!pendingApkPath) return;
    const apkPath = pendingApkPath;
    apkInstallDialog.ok.disabled = true;
    try {
      const job = await RequestApi.startFileJob({ op: "install_apk", sources: [apkPath] });
      pendingApkPath = "";
      model.activeJob = job;
      ui.hideModal(apkInstallDialog.modal);
      renderAll();
      updateJobBar(job);
      startJobPolling();
    } catch (error) {
      alert(error?.message || "APK 安装任务启动失败");
    } finally {
      apkInstallDialog.ok.disabled = false;
    }
  }

  function openDeleteConfirm() {
    pendingOperation = null;
    const context = currentActionContext();
    if (!context || model.panes[context.pane].archive) return;
    pendingOperation = {
      operation: "delete",
      sourcePane: context.pane,
      sources: context.paths.slice(),
      destination: "",
    };
    ui.hideModal(action.modal);
    deleteDialog.message.textContent = `确定删除 ${pendingOperation.sources.length} 个项目吗？此操作不可恢复。`;
    deleteDialog.target.textContent = pendingOperation.sources.slice(0, 4).join("\n")
      + (pendingOperation.sources.length > 4 ? `\n等 ${pendingOperation.sources.length} 项` : "");
    ui.showModal(deleteDialog.modal);
  }

  async function confirmDelete() {
    if (!pendingOperation?.sources?.length || pendingOperation.operation !== "delete") return;
    deleteDialog.ok.disabled = true;
    try {
      const job = await RequestApi.startFileJob({ op: "delete", sources: pendingOperation.sources, conflict: "skip" });
      model.activeJob = job;
      model.clearSelection();
      ui.hideModal(deleteDialog.modal);
      pendingOperation = null;
      renderAll();
      updateJobBar(job);
      startJobPolling();
    } catch (error) {
      alert(error?.message || "无法启动删除任务");
    } finally {
      deleteDialog.ok.disabled = false;
    }
  }

  function isJobRunning(job = model.activeJob) { return !!job && ['scanning', 'running', 'cancelling'].includes(job.state); }
  function scheduleJobCleanup(job) {
    clearTimeout(jobCleanupTimer);
    if (!job?.id || isJobRunning(job)) return;
    const id = job.id;
    jobCleanupTimer = setTimeout(() => {
      if (!stopped && model.activeJob?.id === id && !isJobRunning()) {
        model.activeJob = null; elements.jobBar.hidden = true; renderSelection();
      }
    }, 2400);
  }
  function updateJobBar(job) {
    scheduleJobCleanup(job);
    const active = job && ["scanning", "running", "cancelling"].includes(job.state);
    const visible = !!job && job.state !== "idle" && job.state !== "not_found";
    elements.jobBar.hidden = !visible;
    elements.selectionBar.hidden = active || !model.selectionPane;
    if (!visible) { window.SKAppShell?.setTask("files", pendingResume ? { active: false, label: "文件准备完成", view: "files", resume: resumePrepared } : null); return; }
    const operationNames = { copy: "复制", move: "移动", delete: "删除", extract: "解压",
      properties: "修改属性", compress: "ZIP 压缩", install_apk: "APK 安装" };
    const stateNames = { scanning: "正在扫描", running: "正在处理", cancelling: "正在取消", completed: "任务完成", failed: "任务失败", cancelled: "已取消" };
    elements.jobTitle.textContent = `${stateNames[job.state] || job.state} · ${operationNames[job.operation] || job.operation || "文件"}`;
    const total = Number(job.totalBytes) || Number(job.totalItems) || 0;
    const done = Number(job.totalBytes) ? Number(job.processedBytes) : Number(job.processedItems);
    const percent = total > 0 ? Math.min(100, Math.round(done / total * 100)) : (active ? 0 : 100);
    elements.jobPercent.textContent = job.state === "scanning" ? "扫描中" : `${percent}%`;
    elements.jobProgress.style.width = `${percent}%`;
    elements.jobDetail.textContent = `${Number(job.processedItems) || 0}/${Number(job.totalItems) || 0} 项 · 成功 ${job.successCount || 0} · 跳过 ${job.skippedCount || 0} · 失败 ${job.failedCount || 0} · 警告 ${job.warningCount || 0}${job.outputPath ? ` · 输出 ${job.outputPath}` : ""}${job.resultMessage ? ` · ${job.resultMessage}` : ""}${job.currentPath ? ` · ${job.currentPath}` : ""}`;
    window.SKAppShell?.setTask('files', {
      active, state: active ? job.state : job.state === 'failed' ? 'failed' : 'completed',
      label: elements.jobTitle.textContent, detail: elements.jobDetail.textContent, progress: percent, view: 'files',
      ...(pendingResume ? { resume: resumePrepared } : {}),
    });
    elements.jobCancel.hidden = !active;
    elements.jobCancel.disabled = jobCancelInFlight || job.state === "cancelling";
  }

  async function resumePrepared() {
    const next = pendingResume; pendingResume = null;
    window.SKAppShell?.setTask('files', null);
    if (next) await next();
  }

  async function pollJob() {
    if (!model.activeJob?.id || stopped || jobPollInFlight || jobCancelInFlight) return;
    const id = model.activeJob.id, epoch = jobPollEpoch;
    const current = () => !stopped && epoch === jobPollEpoch && model.activeJob?.id === id;
    let delay = 500;
    jobPollInFlight = true;
    try {
      const job = await RequestApi.getFileJob(id);
      if (!current()) return;
      model.activeJob = job;
      updateJobBar(job);
      if (["scanning", "running", "cancelling"].includes(job.state)) {
        return;
      }
      await Promise.all([
        refreshPane("left"),
        refreshPane("right"),
      ]);
      if (!current()) return;
      const continuation = jobContinuation;
      jobContinuation = null;
      if (continuation && job.state === "completed" && Number(job.failedCount || 0) === 0) {
        if (window.SKAppShell.activeView === 'files' && !document.body.classList.contains('has-overlay')) await continuation();
        else { pendingResume = continuation; updateJobBar(job); }
      } else if (continuation) ui.showToast("文件准备失败，未继续执行", 2400);
      if (job.operation === "compress" && job.state === "completed" && job.outputPath) {
        ui.showToast(`ZIP 已生成：${job.outputPath}`, 2600);
      } else if (job.operation === "install_apk" && job.state === "completed") {
        ui.showToast("APK 安装完成", 2200);
      } else if (job.operation === "install_apk" && job.state === "failed") {
        const detail = job.errors?.[0]?.message || job.resultMessage || "APK 安装失败";
        if (window.SKAppShell.activeView === "files") alert(`${detail}${job.requestId ? `\n请求 ID：${job.requestId}` : ""}`);
        else ui.showToast(detail, 2600);
      }
    } catch (error) {
      if (current()) elements.jobDetail.textContent = error?.message || "任务状态读取失败";
      delay = 1200;
    } finally {
      jobPollInFlight = false;
      if (!stopped && !jobCancelInFlight && model.activeJob?.id && ["scanning", "running", "cancelling"].includes(model.activeJob.state)) {
        clearTimeout(jobPollTimer);
        jobPollTimer = setTimeout(pollJob, delay);
      }
    }
  }

  function startJobPolling() {
    clearTimeout(jobPollTimer);
    if (polledJobId !== model.activeJob?.id) { polledJobId = model.activeJob?.id || ""; ++jobPollEpoch; }
    if (!stopped && !jobPollInFlight && !jobCancelInFlight && model.activeJob?.id && ["scanning", "running", "cancelling"].includes(model.activeJob.state)) {
      jobPollTimer = setTimeout(pollJob, 80);
    }
  }

  async function resumeCurrentJob() {
    const epoch = jobPollEpoch, previousId = model.activeJob?.id;
    try {
      const job = await RequestApi.getFileJob();
      if (stopped || epoch !== jobPollEpoch || model.activeJob?.id !== previousId) return;
      if (job?.id && job.state !== "idle" && job.state !== "not_found") {
        model.activeJob = job;
        updateJobBar(job);
        startJobPolling();
      }
    } catch (_) {}
  }

  async function cancelCurrentJob() {
    if (!model.activeJob?.id || jobCancelInFlight) return;
    const id = model.activeJob.id, epoch = ++jobPollEpoch;
    jobCancelInFlight = true;
    clearTimeout(jobPollTimer);
    elements.jobCancel.disabled = true;
    try {
      const job = await RequestApi.cancelFileJob(id);
      if (stopped || epoch !== jobPollEpoch || model.activeJob?.id !== id) return;
      ++jobPollEpoch;
      jobContinuation = null;
      model.activeJob = job;
      updateJobBar(job);
    } catch (error) {
      if (!stopped && epoch === jobPollEpoch && model.activeJob?.id === id) ui.showToast(error?.message || "取消任务失败", 2200);
    } finally {
      jobCancelInFlight = false;
      if (!stopped) { updateJobBar(model.activeJob); startJobPolling(); }
    }
  }

  function openRename() {
    if (actionContext?.kind !== "single") return;
    const item = actionContext.items[0];
    ui.hideModal(action.modal);
    renameDialog.title.textContent = item.isDir ? "重命名文件夹" : "重命名文件";
    renameDialog.label.textContent = "新名称";
    renameDialog.oldName.textContent = item.path;
    renameDialog.input.value = item.name;
    ui.showModal(renameDialog.modal);
  }

  async function confirmRename() {
    if (actionContext?.kind !== "single") return;
    const item = actionContext.items[0];
    let name;
    try { name = validateName(renameDialog.input.value, "新名称"); }
    catch (error) { alert(error.message); return; }
    if (name === item.name) { ui.hideModal(renameDialog.modal); return; }
    renameDialog.ok.disabled = true;
    try {
      await RequestApi.renamePath(item.path, joinPath(parentPath(item.path), name));
      ui.hideModal(renameDialog.modal);
      await loadPane(item.pane, model.panes[item.pane].path, { activate: false });
    } catch (error) {
      alert(error?.message || "重命名失败");
    } finally {
      renameDialog.ok.disabled = false;
    }
  }

  function openMkdir() {
    elements.overflow.hidden = true;
    mkdirDialog.parent.textContent = model.panes[model.activePane].path;
    mkdirDialog.input.value = "";
    ui.showModal(mkdirDialog.modal);
  }

  async function confirmMkdir() {
    let name;
    try { name = validateName(mkdirDialog.input.value, "文件夹名称"); }
    catch (error) { alert(error.message); return; }
    const pane = model.activePane;
    mkdirDialog.ok.disabled = true;
    try {
      await RequestApi.makeDirectory(joinPath(model.panes[pane].path, name));
      ui.hideModal(mkdirDialog.modal);
      await loadPane(pane, model.panes[pane].path, { activate: false });
    } catch (error) {
      alert(error?.message || "新建文件夹失败");
    } finally {
      mkdirDialog.ok.disabled = false;
    }
  }

  function openCreateFile() {
    elements.overflow.hidden = true;
    const pane = model.activePane;
    createFileSnapshot = { pane, parent: model.panes[pane].path };
    createFileDialog.parent.textContent = createFileSnapshot.parent;
    createFileDialog.input.value = "";
    ui.showModal(createFileDialog.modal);
  }

  async function confirmCreateFile() {
    if (!createFileSnapshot) return;
    let name;
    try { name = validateFileName(createFileDialog.input.value); }
    catch (error) { alert(error.message); return; }
    const snapshot = createFileSnapshot;
    createFileDialog.ok.disabled = true;
    try {
      await RequestApi.createFile(joinPath(snapshot.parent, name));
      createFileSnapshot = null;
      ui.hideModal(createFileDialog.modal);
      await loadPane(snapshot.pane, snapshot.parent, { activate: false });
    } catch (error) {
      alert(error?.message || "新建空白文件失败");
    } finally {
      createFileDialog.ok.disabled = false;
    }
  }

  function permissionModeValue() {
    return permissionDialog.checkboxes.reduce((mode, input) =>
      mode | (input.checked ? Number(input.dataset.modeBit) : 0), 0);
  }

  function updatePermissionState() {
    if (!propertiesSession?.properties) return;
    const mode = permissionModeValue();
    permissionDialog.preview.textContent = `${symbolicMode(mode)} (${octalMode(mode)})`;
    const recursive = permissionDialog.recursiveFiles.checked
      || permissionDialog.recursiveDirectories.checked;
    const changed = mode !== propertiesSession.originalMode || recursive;
    permissionDialog.ok.disabled = propertiesSession.properties.type === "symlink" || !changed;
  }

  function propertyTypeName(type) {
    return ({ file: "普通文件", directory: "文件夹", symlink: "符号链接",
      character: "字符设备", block: "块设备", fifo: "管道", socket: "套接字" })[type] || "其它";
  }

  function principalText(name, id, label) {
    return `${name || id} — ${label} ${id}`;
  }

  function renderProperties() {
    const value = propertiesSession.properties;
    propertiesDialog.type.textContent = propertyTypeName(value.type);
    propertiesDialog.size.textContent = value.type === "directory" ? "—" : formatBytes(value.size);
    propertiesDialog.mtime.textContent = new Date(Number(value.mtimeMs) || 0).toLocaleString();
    propertiesDialog.mode.textContent = `${value.symbolic} (${value.modeOctal})`;
    propertiesDialog.owner.textContent = principalText(value.ownerName, value.uid, "UID");
    propertiesDialog.group.textContent = principalText(value.groupName, value.gid, "GID");
    propertiesDialog.linkRow.hidden = !value.symlinkTarget;
    propertiesDialog.link.textContent = value.symlinkTarget || "";
    propertiesDialog.loading.hidden = true;
    propertiesDialog.content.hidden = false;
    propertiesDialog.editMode.disabled = value.type === "symlink" || isJobRunning();
    propertiesDialog.editOwner.disabled = isJobRunning();
  }

  async function openProperties() {
    if (actionContext?.kind !== "single") return;
    const item = actionContext.items[0];
    ui.hideModal(action.modal);
    propertiesSession = { item, properties: null, principals: { users: [], groups: [] }, originalMode: 0 };
    propertiesDialog.path.textContent = item.path;
    propertiesDialog.loading.hidden = false;
    propertiesDialog.content.hidden = true;
    ui.showModal(propertiesDialog.modal);
    try {
      const [properties, principals] = await Promise.all([
        RequestApi.getFileProperties(item.path),
        RequestApi.listPrincipals(item.path),
      ]);
      if (!propertiesSession || propertiesSession.item.path !== item.path) return;
      propertiesSession.properties = properties;
      propertiesSession.principals = principals || { users: [], groups: [] };
      propertiesSession.originalMode = parseInt(properties.modeOctal || "0", 8) || 0;
      renderProperties();
    } catch (error) {
      ui.hideModal(propertiesDialog.modal);
      propertiesSession = null;
      alert(error?.message || "读取属性失败");
    }
  }

  function openPermissionEditor() {
    if (!propertiesSession?.properties) return;
    const value = propertiesSession.properties;
    const mode = propertiesSession.originalMode;
    for (const input of permissionDialog.checkboxes) {
      input.checked = (mode & Number(input.dataset.modeBit)) !== 0;
      input.disabled = value.type === "symlink";
    }
    permissionDialog.recursiveFiles.checked = false;
    permissionDialog.recursiveDirectories.checked = false;
    permissionDialog.recursive.hidden = !value.recursiveEligible;
    permissionDialog.symlinkNote.hidden = value.type !== "symlink";
    ui.hideModal(propertiesDialog.modal);
    ui.showModal(permissionDialog.modal);
    updatePermissionState();
  }

  function fillPrincipalList(element, values) {
    element.innerHTML = (values || []).map(value =>
      `<option value="${ui.safeHtml(value.name || value.id)}">${ui.safeHtml(value.name || value.id)} — ${ui.safeHtml(value.id)}</option>`).join("");
  }

  function updateOwnershipState() {
    if (!propertiesSession?.properties) return;
    const value = propertiesSession.properties;
    const initialUser = value.ownerName || value.uid;
    const initialGroup = value.groupName || value.gid;
    const recursive = ownershipDialog.recursiveFiles.checked
      || ownershipDialog.recursiveDirectories.checked;
    ownershipDialog.ok.disabled = !recursive
      && ownershipDialog.user.value.trim() === String(initialUser)
      && ownershipDialog.group.value.trim() === String(initialGroup);
  }

  function openOwnershipEditor() {
    if (!propertiesSession?.properties) return;
    const value = propertiesSession.properties;
    ownershipDialog.user.value = value.ownerName || value.uid;
    ownershipDialog.group.value = value.groupName || value.gid;
    ownershipDialog.userCurrent.textContent = principalText(value.ownerName, value.uid, "UID");
    ownershipDialog.groupCurrent.textContent = principalText(value.groupName, value.gid, "GID");
    fillPrincipalList(ownershipDialog.userList, propertiesSession.principals?.users);
    fillPrincipalList(ownershipDialog.groupList, propertiesSession.principals?.groups);
    ownershipDialog.recursiveFiles.checked = false;
    ownershipDialog.recursiveDirectories.checked = false;
    ownershipDialog.recursive.hidden = !value.recursiveEligible;
    ui.hideModal(propertiesDialog.modal);
    ui.showModal(ownershipDialog.modal);
    updateOwnershipState();
  }

  async function startPropertiesChange(values) {
    if (!propertiesSession?.item) return;
    const item = propertiesSession.item;
    try {
      const job = await RequestApi.startFileJob({
        op: "properties",
        sources: [item.path],
        properties: values,
      });
      model.activeJob = job;
      ui.hideModal(permissionDialog.modal);
      ui.hideModal(ownershipDialog.modal);
      ui.hideModal(propertiesDialog.modal);
      propertiesSession = null;
      updateJobBar(job);
      startJobPolling();
    } catch (error) {
      alert(error?.message || "属性修改任务启动失败");
    }
  }

  async function confirmPermissionChange() {
    permissionDialog.ok.disabled = true;
    await startPropertiesChange({
      mode: octalMode(permissionModeValue()),
      recursiveFiles: permissionDialog.recursiveFiles.checked,
      recursiveDirectories: permissionDialog.recursiveDirectories.checked,
    });
    updatePermissionState();
  }

  async function confirmOwnershipChange() {
    if (!propertiesSession?.properties) return;
    const value = propertiesSession.properties;
    const recursive = ownershipDialog.recursiveFiles.checked
      || ownershipDialog.recursiveDirectories.checked;
    const properties = {
      recursiveFiles: ownershipDialog.recursiveFiles.checked,
      recursiveDirectories: ownershipDialog.recursiveDirectories.checked,
    };
    const user = ownershipDialog.user.value.trim();
    const group = ownershipDialog.group.value.trim();
    if (!user || !group) {
      alert("所有者和用户组不能为空");
      return;
    }
    if (recursive || user !== String(value.ownerName || value.uid)) properties.owner = user;
    if (recursive || group !== String(value.groupName || value.gid)) properties.group = group;
    ownershipDialog.ok.disabled = true;
    await startPropertiesChange(properties);
    updateOwnershipState();
  }

  async function openTextEditor(item) {
    ui.hideModal(action.modal);
    return textEditor.open(item);
  }

  async function getHideDir() {
    if (hideDirCache) return hideDirCache;
    hideDirCache = String(await RequestApi.getHideDir() || "").trim();
    if (!hideDirCache) throw new Error("获取隐藏目录失败");
    return hideDirCache;
  }

  async function resolvePreparedFile(filePath, options = {}) {
    const fileType = await RequestApi.checkFileType(filePath);
    if (fileType === "shell_script") return { sourceFile: filePath, resolvedFile: filePath, fileType, needsCopy: false };
    if (fileType === "executable_arm64" || fileType === "executable_arm32") {
      // 自动化执行器会在每次运行时检测 noexec，并把 ELF 临时复制到隐藏目录；
      // 草稿始终保存原始路径，避免方案引用一次性副本。
      if (options.deferNoExecCopy) {
        return { sourceFile: filePath, resolvedFile: filePath, fileType, needsCopy: false };
      }
      const dir = window.SKTerminalCore.getPathDir(filePath);
      const mountState = await RequestApi.checkExecMount(dir);
      if (mountState === "can exec") return { sourceFile: filePath, resolvedFile: filePath, fileType, needsCopy: false };
      if (mountState === "can not exec") {
        const hideDir = await getHideDir();
        return { sourceFile: filePath, resolvedFile: joinPath(hideDir, filePath.split("/").pop()), fileType, needsCopy: true };
      }
      throw new Error(`执行目录检测结果异常：${mountState || "未知"}`);
    }
    throw new Error(`当前文件不支持直接执行：${fileType || "未知类型"}`);
  }

  function showPreparedModal() {
    if (!pendingPreparedFile) return;
    if (pendingMode === "exec") {
      execDialog.code.textContent = pendingPreparedFile.resolvedFile;
      execDialog.args.value = "";
      ui.showModal(execDialog.modal);
    } else {
      autoDialog.code.textContent = pendingPreparedFile.resolvedFile;
      autoDialog.args.value = "";
      ui.showModal(autoDialog.modal);
    }
  }

  async function prepareAndOpenFlow(mode) {
    if (actionContext?.kind !== "single") return;
    pendingMode = mode;
    pendingPreparedFile = null;
    try {
      pendingPreparedFile = await resolvePreparedFile(actionContext.paths[0], {
        deferNoExecCopy: mode === "auto",
      });
      ui.hideModal(action.modal);
      if (pendingPreparedFile.needsCopy) {
        execMountDialog.target.innerHTML = `<div class="modal-path-from">当前文件：${ui.safeHtml(pendingPreparedFile.sourceFile)}</div>
          <div class="modal-path-to">将复制到：${ui.safeHtml(pendingPreparedFile.resolvedFile)}</div>`;
        ui.showModal(execMountDialog.modal);
      } else {
        showPreparedModal();
      }
    } catch (error) {
      alert(error?.message || "文件检查失败");
    }
  }

  async function copyPreparedFileAndContinue() {
    if (!pendingPreparedFile?.needsCopy) return;
    execMountDialog.ok.disabled = true;
    try {
      const destination = parentPath(pendingPreparedFile.resolvedFile);
      const job = await RequestApi.startFileJob({
        op: "copy",
        sources: [pendingPreparedFile.sourceFile],
        destination,
        conflict: "overwrite",
      });
      pendingPreparedFile.needsCopy = false;
      model.activeJob = job;
      ui.hideModal(execMountDialog.modal);
      updateJobBar(job);
      jobContinuation = async () => showPreparedModal();
      startJobPolling();
    } catch (error) {
      alert(error?.message || "拷贝失败");
    } finally {
      execMountDialog.ok.disabled = false;
    }
  }

  function buildPendingCommand(rawArgs) {
    if (!pendingPreparedFile) throw new Error("当前没有可执行文件");
    if (pendingPreparedFile.fileType === "shell_script") {
      return window.SKTerminalCore.buildShCommand(pendingPreparedFile.resolvedFile, rawArgs);
    }
    return window.SKTerminalCore.buildExecCommand(pendingPreparedFile.resolvedFile, rawArgs);
  }

  async function executeImmediateCommand(finalCommand) {
    throw new Error('独立 SUSFS 文件页不执行终端命令');
  }

  async function submitPreparedCommand() {
    if (!pendingPreparedFile) return;
    if (pendingMode === "exec") {
      let command;
      try { command = buildPendingCommand(execDialog.args.value); }
      catch (error) { alert(error.message); return; }
      ui.hideModal(execDialog.modal);
      await executeImmediateCommand(command);
      return;
    }
    let args;
    try { args = window.SKTerminalCore.splitShellArgs(autoDialog.args.value); }
    catch (error) { alert(error.message); return; }
    if (!window.SKInputSimulator?.appendScript) {
      alert("输入模拟器尚未加载");
      return;
    }
    quickTaskDialog.ok.disabled = true;
    try {
      await window.SKInputSimulator.appendScript(pendingPreparedFile.sourceFile, args);
      ui.hideModal(quickTaskDialog.modal);
      ui.hideModal(autoDialog.modal);
      await window.SKAppShell.navigate("terminal");
      app.openAutoSheet?.("editor");
    } catch (error) {
      alert(error?.message || "追加至输入模拟器失败");
    } finally {
      quickTaskDialog.ok.disabled = false;
    }
  }

  function openPathEditor() {
    elements.pathInput.value = model.panes[model.activePane].path;
    elements.pathText.hidden = true;
    elements.pathEditor.hidden = false;
    elements.pathText.setAttribute("aria-expanded", "true");
    ui.focusWithoutKeyboard(elements.pathEditor);
  }

  function closePathEditor() {
    elements.pathText.hidden = false;
    elements.pathEditor.hidden = true;
    elements.pathText.setAttribute("aria-expanded", "false");
  }

  async function submitPath() {
    const pane = model.activePane;
    const path = normalizePath(elements.pathInput.value || model.panes[pane].path);
    closePathEditor();
    await loadPane(pane, path, { recordRecent: true });
  }

  archiveBrowser = window.SKArchiveBrowser.create({
    model, api: RequestApi, normalizeEntry,
    render(pane) { renderPane(pane, false); renderSelection(); },
    invalidatePane(pane) { ++loadSequence[pane]; },
  });
  textEditor = window.SKTextEditor.create({
    root: document.getElementById("textEditor"), api: RequestApi,
    onSaved(item) { return refreshPane(item.pane); },
    canSave() { return !model.activeJob || !["scanning", "running", "cancelling"].includes(model.activeJob.state); },
  });
  imageViewer = window.SKImageViewer.create({ api: RequestApi });
  installIcons();
  attachListEvents("left");
  attachListEvents("right");
  attachPlacesEvents();

  window.SKAppShell.register('files', { activate: activateWorkspace, deactivate: deactivateWorkspace, back: backInWorkspace, beforeLeave: beforeLeaveWorkspace });
  elements.close.onclick = () => window.SKAppShell.navigate('susfs');
  elements.pickerCancel.onclick = () => finishFilePicker({ cancelled: true, reason: 'cancel' });
  elements.pickerDirectory.onclick = async () => {
    const session = filePicker, pane = model.activePane, state = model.panes[pane];
    if (!session || session.purpose !== 'susfs-config-export' || session.preparing || session.choosing || state.loading || state.error || state.archive) return;
    session.choosing = true;
    try {
      const properties = await RequestApi.getFileProperties(state.path);
      if (filePicker !== session) return;
      if (properties.type !== 'directory') throw new Error('请选择实际目录');
      finishFilePicker({path:state.path,pane});
    } catch(error) {if(filePicker===session){session.choosing=false;ui.showToast(error?.message||'目录不可用',2200);}}
  };
  document.getElementById('filePlacesButton').onclick = openPlaces;
  document.getElementById('fileSelectMode').onclick = () => { elements.overflow.hidden = true; actionContext = null; model.beginSelection(model.activePane); renderAll(); };
  elements.pathTrigger.onclick = event => {
    if (event.target.closest(".fm-path-editor")) return;
    openPathEditor();
  };
  elements.pathGo.onclick = event => { event.stopPropagation(); submitPath(); };
  elements.pathInput.onkeydown = event => {
    if (["Enter", "NumpadEnter", "Go", "Search"].includes(event.key) || event.code === "Enter") {
      event.preventDefault();
      event.stopPropagation();
      submitPath();
    }
    if (event.key === "Escape") { event.stopPropagation(); closePathEditor(); elements.pathText.focus(); }
  };
  elements.menuButton.onclick = event => {
    event.stopPropagation();
    elements.overflow.hidden = !elements.overflow.hidden;
  };
  document.addEventListener("click", event => {
    if (!event.target.closest("#fileOverflowMenu") && !event.target.closest("#fileMenuBtn")) elements.overflow.hidden = true;
  });
  elements.refresh.onclick = () => {
    elements.overflow.hidden = true;
    const pane = model.activePane;
    if (model.panes[pane].archive) archiveBrowser.refresh(pane);
    else refreshPane(pane);
  };
  elements.mkdir.onclick = openMkdir;
  elements.newFile.onclick = openCreateFile;
  elements.setHome.onclick = async () => {
    elements.overflow.hidden = true;
    const pane = model.activePane;
    try {
      await RequestApi.setFileHome(pane, model.panes[pane].path);
      model.setHome(pane, model.panes[pane].path);
      ui.showToast(`${pane === "left" ? "左" : "右"}栏首页已设置`, 1500);
    } catch (error) {
      alert(error?.message || "首页设置失败");
    }
  };
  elements.addBookmark.onclick = async () => {
    elements.overflow.hidden = true;
    const pane = model.activePane;
    if (model.panes[pane].error) {
      alert("当前目录读取失败，请进入有效目录后再添加书签");
      return;
    }
    await addBookmarkPath(model.panes[pane].path);
  };
  elements.swap.onclick = () => {
    elements.overflow.hidden = true;
    model.panes.left.scrollTop = elements.listLeft.scrollTop;
    model.panes.right.scrollTop = elements.listRight.scrollTop;
    if (model.panes.left.loading && !model.panes.left.archive || model.panes.right.loading && !model.panes.right.archive) {
      ui.showToast("请等待目录读取完成", 1500); return;
    }
    model.swapPanes();
    renderAll();
  };
  elements.sync.onclick = () => {
    elements.overflow.hidden = true;
    model.panes.left.scrollTop = elements.listLeft.scrollTop;
    model.panes.right.scrollTop = elements.listRight.scrollTop;
    const source = model.activePane;
    if (model.panes[source].archive) { ui.showToast("压缩包视图不支持同步", 1500); return; }
    const target = model.otherPane(source);
    ++loadSequence[target];
    archiveBrowser.leave(target);
    model.syncPanesToActive();
    renderAll();
    ui.showToast(`已按${source === "left" ? "左" : "右"}栏同步窗口`, 1500);
  };
  elements.paneLeft.addEventListener("pointerdown", () => activatePane("left"));
  elements.paneRight.addEventListener("pointerdown", () => activatePane("right"));

  elements.placesRecentTab.onclick = () => setPlacesTab("recent");
  elements.placesBookmarkTab.onclick = () => setPlacesTab("bookmark");
  elements.placesClose.onclick = closePlaces;
  elements.placesBackdrop.onclick = closePlaces;

  placeAction.cancel.onclick = () => { placeActionContext = null; ui.hideModal(placeAction.modal); };
  placeAction.addBookmark.onclick = async () => {
    const path = placeActionContext?.path;
    placeActionContext = null;
    ui.hideModal(placeAction.modal);
    if (path) await addBookmarkPath(path);
  };
  placeAction.editNote.onclick = openBookmarkNote;
  placeAction.delete.onclick = deletePlace;
  bookmarkNoteDialog.cancel.onclick = () => {
    bookmarkNotePath = "";
    ui.hideModal(bookmarkNoteDialog.modal);
  };
  bookmarkNoteDialog.ok.onclick = saveBookmarkNote;
  bookmarkNoteDialog.input.onkeydown = event => {
    if (event.key === "Enter") {
      event.preventDefault();
      saveBookmarkNote();
    }
  };

  elements.selectionAll.onclick = () => { if (model.selectAll() === false) ui.showToast("一次最多选择 500 项", 1800); renderAll(); };
  elements.selectionInvert.onclick = () => { if (model.invertSelection() === false) ui.showToast("一次最多选择 500 项", 1800); renderAll(); };
  elements.selectionExit.onclick = () => { model.clearSelection(); renderAll(); };
  elements.selectionActions.onclick = showBatchAction;
  elements.jobCancel.onclick = cancelCurrentJob;

  action.cancel.onclick = () => { actionContext = null; ui.hideModal(action.modal); };
  action.copy.onclick = () => openOperationConfirm("copy");
  action.move.onclick = () => openOperationConfirm("move");
  action.compress.onclick = () => openOperationConfirm("compress");
  action.extract.onclick = () => openOperationConfirm("extract");
  action.installApk.onclick = openApkInstallConfirm;
  action.edit.onclick = () => actionContext?.items?.[0] && openTextEditor(actionContext.items[0]);
  action.image.onclick = () => { ui.hideModal(action.modal); if (actionContext?.items?.[0]) imageViewer.open(actionContext.items[0]); };
  action.browse.onclick = () => { ui.hideModal(action.modal); const item = actionContext?.items?.[0]; if (item) archiveBrowser.open(item.pane, item.path); };
  action.rename.onclick = openRename;
  action.delete.onclick = openDeleteConfirm;
  if (action.exec) action.exec.onclick = null;
  if (action.auto) action.auto.onclick = null;
  action.properties.onclick = openProperties;
  action.susfsDetails.onclick = () => {
    if (!canUseSusfs()) return;
    const path = actionContext?.paths?.[0];
    ui.hideModal(action.modal);
    if (path) window.SKSusfsConsole?.inspect(path);
  };
  action.susfs.onclick = () => {
    const context = currentActionContext();
    if (!canUseSusfs() || !context) return;
    const snapshot = { pane: context.pane, paths: context.paths.slice(), items: context.items.map(item => ({ ...item })) };
    ui.hideModal(action.modal); window.SKSusfsConsole?.openSelection(snapshot);
  };
  action.susfsTarget.onclick = () => {
    const context = currentActionContext();
    if (!canUseSusfs() || !context) return;
    const snapshot = { pane: context.pane, paths: context.paths.slice(), items: context.items.map(item => ({ ...item })) };
    ui.hideModal(action.modal); window.SKSusfsConsole?.chooseTarget(snapshot);
  };

  operationConfirm.cancel.onclick = () => {
    pendingOperation = null;
    operationConfirm.conflicts.hidden = false;
    ui.hideModal(operationConfirm.modal);
  };
  operationConfirm.ok.onclick = startPendingOperation;
  apkInstallDialog.cancel.onclick = () => {
    pendingApkPath = "";
    ui.hideModal(apkInstallDialog.modal);
  };
  apkInstallDialog.ok.onclick = confirmApkInstall;
  deleteDialog.cancel.onclick = () => { pendingOperation = null; ui.hideModal(deleteDialog.modal); };
  deleteDialog.ok.onclick = confirmDelete;
  renameDialog.cancel.onclick = () => ui.hideModal(renameDialog.modal);
  renameDialog.ok.onclick = confirmRename;
  mkdirDialog.cancel.onclick = () => ui.hideModal(mkdirDialog.modal);
  mkdirDialog.ok.onclick = confirmMkdir;
  createFileDialog.cancel.onclick = () => { createFileSnapshot = null; ui.hideModal(createFileDialog.modal); };
  createFileDialog.ok.onclick = confirmCreateFile;
  createFileDialog.input.onkeydown = event => {
    if (event.key === "Enter") { event.preventDefault(); confirmCreateFile(); }
  };

  propertiesDialog.close.onclick = () => { propertiesSession = null; ui.hideModal(propertiesDialog.modal); };
  propertiesDialog.editMode.onclick = openPermissionEditor;
  propertiesDialog.editOwner.onclick = openOwnershipEditor;
  permissionDialog.cancel.onclick = () => {
    ui.hideModal(permissionDialog.modal);
    if (propertiesSession) ui.showModal(propertiesDialog.modal);
  };
  permissionDialog.ok.onclick = confirmPermissionChange;
  for (const input of permissionDialog.checkboxes) input.addEventListener("change", updatePermissionState);
  permissionDialog.recursiveFiles.onchange = updatePermissionState;
  permissionDialog.recursiveDirectories.onchange = updatePermissionState;
  ownershipDialog.cancel.onclick = () => {
    ui.hideModal(ownershipDialog.modal);
    if (propertiesSession) ui.showModal(propertiesDialog.modal);
  };
  ownershipDialog.ok.onclick = confirmOwnershipChange;
  ownershipDialog.user.addEventListener("input", updateOwnershipState);
  ownershipDialog.group.addEventListener("input", updateOwnershipState);
  ownershipDialog.recursiveFiles.onchange = updateOwnershipState;
  ownershipDialog.recursiveDirectories.onchange = updateOwnershipState;

  if (execDialog.cancel) execDialog.cancel.onclick = () => ui.hideModal(execDialog.modal);
  if (execDialog.ok) execDialog.ok.onclick = null;
  if (autoDialog.cancel) autoDialog.cancel.onclick = () => ui.hideModal(autoDialog.modal);
  if (autoDialog.ok) autoDialog.ok.onclick = null;
  if (quickTaskDialog.cancel) quickTaskDialog.cancel.onclick = () => ui.hideModal(quickTaskDialog.modal);
  if (quickTaskDialog.ok) quickTaskDialog.ok.onclick = null;
  if (execMountDialog.cancel) execMountDialog.cancel.onclick = () => { pendingPreparedFile = null; ui.hideModal(execMountDialog.modal); };
  if (execMountDialog.ok) execMountDialog.ok.onclick = null;


  window.SKFileManager = {
    open: openWorkspace,
    pickFile,
    isPickingFile: () => !!filePicker,
    close: () => window.SKAppShell.navigate("susfs"),
    loadDir(path, pane = model.activePane) { return loadPane(pane, path, { recordRecent: true }); },
    model,
    refreshRuleBadges() { decorateRuleBadges('left'); decorateRuleBadges('right'); },
  };

  window.SKSusfsAvailability?.subscribe(() => {
    updateSusfsActions();
    decorateRuleBadges('left');
    decorateRuleBadges('right');
  });

  const previousCloseAllSheets = app.closeAllSheets;
  app.closeAllSheets = () => {
    if (typeof previousCloseAllSheets === "function") previousCloseAllSheets();
    closeWorkspace();
  };
})();
