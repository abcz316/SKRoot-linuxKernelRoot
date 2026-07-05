(() => {
  const app = window.SKRootApp;
  const ui = window.SKUiUtils;
  if (!app || !ui) return;

  const { cmd, fileBtn, autoBtn, sheetOverlay } = app.elements;

  const fileSheet = document.getElementById("fileSheet");
  const fileList = document.getElementById("fileList");
  const fileBack = document.getElementById("fileBack");
  const pathInput = document.getElementById("pathInput");
  const pathGo = document.getElementById("pathGo");
  const fileNewFolder = document.getElementById("fileNewFolder");
  const fileRefresh = document.getElementById("fileRefresh");
  const fileClose = document.getElementById("fileClose");
  const pasteBar = document.getElementById("pasteBar");
  const pasteMode = document.getElementById("pasteMode");
  const pasteSource = document.getElementById("pasteSource");
  const pasteCancel = document.getElementById("pasteCancel");
  const pasteConfirm = document.getElementById("pasteConfirm");

  const actionModal = document.getElementById("actionModal");
  const actionTitle = document.getElementById("actionTitle");
  const actionTarget = document.getElementById("actionTarget");
  const actAuto = document.getElementById("actAuto");
  const actExec = document.getElementById("actExec");
  const actCopy = document.getElementById("actCopy");
  const actCut = document.getElementById("actCut");
  const actRename = document.getElementById("actRename");
  const actionCancel = document.getElementById("actionCancel");

  const execModal = document.getElementById("execModal");
  const execCode = document.getElementById("execCode");
  const argInput = document.getElementById("argInput");
  const execCancel = document.getElementById("execCancel");
  const execConfirm = document.getElementById("execConfirm");

  const autoModal = document.getElementById("autoModal");
  const autoCode = document.getElementById("autoCode");
  const autoArgInput = document.getElementById("autoArgInput");
  const autoCancel = document.getElementById("autoCancel");
  const autoConfirm = document.getElementById("autoConfirm");

  const renameModal = document.getElementById("renameModal");
  const renameTitle = document.getElementById("renameTitle");
  const renameOldName = document.getElementById("renameOldName");
  const renameLabel = document.getElementById("renameLabel");
  const renameInput = document.getElementById("renameInput");
  const renameCancel = document.getElementById("renameCancel");
  const renameConfirm = document.getElementById("renameConfirm");

  const actDelete = document.getElementById("actDelete");
  const deleteModal = document.getElementById("deleteModal");
  const deleteMessage = document.getElementById("deleteMessage");
  const deleteTargetName = document.getElementById("deleteTargetName");
  const deleteCancel = document.getElementById("deleteCancel");
  const deleteConfirm = document.getElementById("deleteConfirm");

  const mkdirModal = document.getElementById("mkdirModal");
  const mkdirParent = document.getElementById("mkdirParent");
  const mkdirInput = document.getElementById("mkdirInput");
  const mkdirCancel = document.getElementById("mkdirCancel");
  const mkdirConfirm = document.getElementById("mkdirConfirm");

  const pasteConflictModal = document.getElementById("pasteConflictModal");
  const pasteConflictTarget = document.getElementById("pasteConflictTarget");
  const pasteConflictCancel = document.getElementById("pasteConflictCancel");
  const pasteConflictConfirm = document.getElementById("pasteConflictConfirm");
  
  const confirmQuickTaskModal = document.getElementById("confirmQuickTaskModal");
  const confirmQuickTaskCancel = document.getElementById("confirmQuickTaskCancel");
  const confirmQuickTaskOk = document.getElementById("confirmQuickTaskOk");

  const execMountModal = document.getElementById("execMountModal");
  const execMountTarget = document.getElementById("execMountTarget");
  const execMountCancel = document.getElementById("execMountCancel");
  const execMountConfirm = document.getElementById("execMountConfirm");

  let currentPath = "/sdcard";
  let currentItem = null;
  let currentFiles = [];
  let clipboardItem = null;
  let pendingPasteCommand = "";
  let longPressTimer = null;
  let longPressHandled = false;
  let longPressHandledAt = 0;
  let touchMoved = false;
  let longPressStartX = 0;
  let longPressStartY = 0;
  let pendingMode = null;
  let pendingPreparedFile = null;
  let hideDirCache = "";

  async function loadDir(path) {
    currentPath = path || "/sdcard";
    pathInput.value = currentPath;
    pathInput.readOnly = true;
    pathGo.style.display = "none";
    fileList.innerHTML = '<div style="padding:20px;text-align:center;color:#94a3b8;font-size:12px">读取中...</div>';
    let files = await RequestApi.listDir(currentPath);
    if (!files) {
      files = [{ name: "modules", isDir: true, date: "2026-03-26", time: "22:10", size: 0}];
    }
    currentFiles = Array.isArray(files) ? files : [];
    renderFiles(currentFiles);
    updatePasteBar();
  }

  function renderFiles(files) {
    fileList.innerHTML = files.map(f => {
      const isProtected = !!(f.hideProtected);
      const icon = f.isDir ? "📁" : (f.canExec ? '<span style="color:#9333ea">⚙️</span>' : "📄");
      const fullPath = ui.joinPath(currentPath, f.name);
      const displaySize = f.isDir ? "文件夹" : ui.formatBytes(f.size);
      const metaText = isProtected ? `隐藏保护中 · ${displaySize}` : displaySize;
      const protectedMark = isProtected
        ? `<span class="file-protected-mark" aria-label="隐藏保护中" title="隐藏保护中"></span>`
        : '';
      return `
        <div class="file-row${isProtected ? ' is-protected' : ''}" data-path="${ui.safeHtml(fullPath)}" data-isdir="${!!f.isDir}" data-exec="${!!f.canExec}" data-protected="${isProtected}">
          <div class="file-icon">${icon}</div>
          <div class="file-info">
            <div class="file-name">${ui.safeHtml(f.name)}</div>
            <div class="file-meta">${protectedMark}<span>${ui.safeHtml(metaText)}</span></div>
          </div>
        </div>
      `;
    }).join('');
    fileList.scrollTop = 0;
  }

  function openFileSheet() {
    autoBtn.classList.remove("active");
    fileBtn.classList.add("active");
    fileSheet.classList.add("show");
    sheetOverlay.classList.add("show");
    loadDir(currentPath);
  }

  function closeFileSheet() {
    fileBtn.classList.remove("active");
    fileSheet.classList.remove("show");
    pathInput.readOnly = true;
    pathGo.style.display = "none";
    if (!document.getElementById("autoSheet").classList.contains("show")) {
      sheetOverlay.classList.remove("show");
    }
  }

  function getFileBaseName(filePath) {
    return String(filePath || "").split('/').pop() || "";
  }

  function normalizePath(path) {
    const raw = String(path || "/").replace(/\/+/g, "/");
    if (raw.length > 1) return raw.replace(/\/+$/, "");
    return raw || "/";
  }

  function getCurrentFilePath() {
    return currentItem?.path || "";
  }

  function getKindName(item = currentItem) {
    return item?.isDir ? "文件夹" : "文件";
  }

  function findItemByName(name) {
    return currentFiles.find(item => item && item.name === name);
  }

  function targetExists(name) {
    return !!findItemByName(name);
  }

  function buildItem(path, isDir) {
    return {
      path: normalizePath(path),
      isDir: !!isDir,
      name: getFileBaseName(path),
    };
  }

  function openActionMenu(item) {
    currentItem = item;
    const kindName = getKindName(item);
    actionTitle.textContent = `选择${kindName}操作`;
    actionTarget.textContent = item.path;
    actAuto.style.display = item.isDir ? "none" : "";
    actExec.style.display = item.isDir ? "none" : "";
    actRename.textContent = `✎ 重命名${kindName}`;
    actDelete.textContent = `🗑 删除${kindName}`;
    ui.showModal(actionModal);
  }

  function setClipboard(mode) {
    if (!currentItem) return;
    clipboardItem = {
      mode,
      path: currentItem.path,
      isDir: currentItem.isDir,
      name: currentItem.name,
    };
    ui.hideModal(actionModal);
    updatePasteBar();
    ui.showToast(mode === "copy" ? "已复制，进入目标目录后粘贴" : "已剪切，进入目标目录后粘贴", 1400);
  }

  function updatePasteBar() {
    if (!pasteBar) return;
    if (!clipboardItem) {
      pasteBar.classList.remove("show");
      pasteMode.textContent = "";
      pasteSource.textContent = "";
      return;
    }
    pasteBar.classList.add("show");
    pasteMode.textContent = clipboardItem.mode === "copy" ? "复制待粘贴" : "移动待粘贴";
    pasteSource.textContent = clipboardItem.path;
  }

  function clearClipboard() {
    clipboardItem = null;
    pendingPasteCommand = "";
    updatePasteBar();
  }

  function buildCopyCommand(srcPath, targetDir) {
    const dir = normalizePath(targetDir);
    return `cp -rf ${window.SKTerminalCore.shellQuote(srcPath)} ${window.SKTerminalCore.shellQuote(dir === "/" ? "/" : dir + "/")}`;
  }

  function buildMoveCommand(srcPath, targetDir) {
    const dir = normalizePath(targetDir);
    return `mv -f ${window.SKTerminalCore.shellQuote(srcPath)} ${window.SKTerminalCore.shellQuote(dir === "/" ? "/" : dir + "/")}`;
  }

  function buildOverwritePasteCommand(baseCommand, targetPath) {
    return `rm -rf ${window.SKTerminalCore.shellQuote(targetPath)} && ${baseCommand}`;
  }

  function isSamePath(a, b) {
    return normalizePath(a) === normalizePath(b);
  }

  function isChildPath(parent, child) {
    const p = normalizePath(parent);
    const c = normalizePath(child);
    return c.length > p.length && c.startsWith(p === "/" ? "/" : p + "/");
  }

  function validateName(name, messagePrefix) {
    const trimmed = String(name || "").trim();
    if (!trimmed) {
      alert(`${messagePrefix}不能为空`);
      return "";
    }
    if (trimmed.includes("/")) {
      alert(`${messagePrefix}不能包含 /`);
      return "";
    }
    if (trimmed === "." || trimmed === "..") {
      alert(`${messagePrefix}不能是 . 或 ..`);
      return "";
    }
    return trimmed;
  }

  function openRenameModal() {
    if (!currentItem) return;
    const kindName = getKindName();
    ui.hideModal(actionModal);
    renameTitle.textContent = `重命名${kindName}`;
    renameLabel.textContent = `新${kindName}名称`;
    renameOldName.textContent = currentItem.path;
    renameInput.value = currentItem.name;
    ui.showModal(renameModal);
    setTimeout(() => renameInput.focus(), 100);
  }

  function openDeleteModal() {
    if (!currentItem) return;
    const kindName = getKindName();
    ui.hideModal(actionModal);
    deleteMessage.textContent = `确定要删除以下${kindName}吗？此操作不可恢复。`;
    deleteTargetName.textContent = currentItem.path;
    ui.showModal(deleteModal);
  }

  function openMkdirModal() {
    mkdirParent.textContent = currentPath;
    mkdirInput.value = "";
    ui.showModal(mkdirModal);
    setTimeout(() => mkdirInput.focus(), 100);
  }

  function getPasteTargetPath() {
    return ui.joinPath(currentPath, clipboardItem?.name || "");
  }

  async function executePasteCommand(command) {
    pendingPasteCommand = "";
    ui.hideModal(pasteConflictModal);
    clearClipboard();
    await executeImmediateCommand(command);
  }

  async function pasteClipboard() {
    if (!clipboardItem) return;
    const srcPath = normalizePath(clipboardItem.path);
    const dstDir = normalizePath(currentPath);
    const dstPath = normalizePath(getPasteTargetPath());

    if (isSamePath(srcPath, dstPath)) {
      alert("不能粘贴到原位置");
      return;
    }
    if (clipboardItem.isDir && (isSamePath(srcPath, dstDir) || isChildPath(srcPath, dstDir))) {
      alert("不能把文件夹移动或复制到自身或子目录");
      return;
    }

    const command = clipboardItem.mode === "copy"
      ? buildCopyCommand(srcPath, dstDir)
      : buildMoveCommand(srcPath, dstDir);

    if (targetExists(clipboardItem.name)) {
      pendingPasteCommand = buildOverwritePasteCommand(command, dstPath);
      pasteConflictTarget.textContent = dstPath;
      ui.showModal(pasteConflictModal);
      return;
    }

    await executePasteCommand(command);
  }

  async function getHideDir() {
    if (hideDirCache) return hideDirCache;
    const dir = String(await RequestApi.getHideDir() || "").trim();
    if (!dir || /^HTTP\s+\d+/i.test(dir)) {
      throw new Error("获取隐藏目录失败，请稍后重试");
    }
    hideDirCache = dir;
    return hideDirCache;
  }

  async function getCopiedTargetPath(filePath) {
    const hideDir = await getHideDir();
    return ui.joinPath(hideDir, getFileBaseName(filePath));
  }

  function clearPendingPreparedFile() {
    pendingPreparedFile = null;
  }

  async function resolvePreparedFile(filePath) {
    const fileType = await RequestApi.checkFileType(filePath);
    if (fileType === "shell_script") return { sourceFile: filePath, resolvedFile: filePath, fileType, needsCopy: false, };
    if (fileType === "executable_arm64" || fileType === "executable_arm32") {
      const dir = window.SKTerminalCore.getPathDir(filePath);
      const mountState = await RequestApi.checkExecMount(dir);
      if (mountState === "can exec") return { sourceFile: filePath, resolvedFile: filePath, fileType, needsCopy: false, };
      if (mountState === "can not exec") return { sourceFile: filePath, resolvedFile: await getCopiedTargetPath(filePath), fileType, needsCopy: true, };
      throw new Error("执行目录检测结果异常：" + (mountState || "未知"));
    }
    throw new Error("当前文件不支持直接执行：" + (fileType || "未知类型"));
  }

  function showPreparedModal() {
    if (!pendingPreparedFile) return;
    if (pendingMode === "exec") {
      execCode.textContent = pendingPreparedFile.resolvedFile;
      argInput.value = "";
      ui.showModal(execModal);
      return;
    }
    if (pendingMode === "simulator") {
      autoCode.textContent = pendingPreparedFile.resolvedFile;
      autoArgInput.value = "";
      ui.showModal(autoModal);
    }
  }

  async function prepareAndOpenFlow(mode) {
    pendingMode = mode;
    clearPendingPreparedFile();
    try {
      const prepared = await resolvePreparedFile(getCurrentFilePath());
      pendingPreparedFile = prepared;
      ui.hideModal(actionModal);
      if (prepared.needsCopy) {
        execMountTarget.innerHTML = `<div class="modal-path-from">当前文件：${ui.safeHtml(prepared.sourceFile)}</div>
<div class="modal-path-to">将复制到：${ui.safeHtml(prepared.resolvedFile)}</div>`;
        ui.showModal(execMountModal);
        return;
      }
      showPreparedModal();
    } catch (e) {
      alert(e.message || "文件检查失败，请稍后重试");
    }
  }

  function buildPendingCommand(rawArgs) {
    if (!pendingPreparedFile) throw new Error("当前没有可执行文件");
    if (pendingPreparedFile.fileType === "shell_script") return window.SKTerminalCore.buildShCommand(pendingPreparedFile.resolvedFile, rawArgs);
    if (pendingPreparedFile.fileType === "executable_arm64" || pendingPreparedFile.fileType === "executable_arm32") return window.SKTerminalCore.buildExecCommand(pendingPreparedFile.resolvedFile, rawArgs);
    throw new Error("当前文件类型不支持执行");
  }

  async function executeImmediateCommand(finalCmd) {
    closeFileSheet();
    cmd.value = finalCmd;
    await app.sendCommand();
  }

  async function submitPreparedCommand(options = {}) {
    const skipConfirm = !!options.skipConfirm;
    if (!pendingPreparedFile) {
      alert("当前没有可执行文件");
      return;
    }

    if (pendingMode === "exec") {
      let finalCmd;
      try {
        finalCmd = buildPendingCommand(argInput.value);
      } catch (e) {
        alert(e.message || "参数格式错误");
        return;
      }
      ui.hideModal(execModal);
      await executeImmediateCommand(finalCmd);
      return;
    }

    if (pendingMode === "simulator") {
      let fullCmd;
      try {
        fullCmd = buildPendingCommand(autoArgInput.value);
      } catch (e) {
        alert(e.message || "参数格式错误");
        return;
      }
      const tasks = window.SKInputSimulator?.getTasks?.() || [];
      const hasContent = tasks.length > 0 && tasks[0].cmd && tasks[0].cmd.trim() !== "";
      if (hasContent && !skipConfirm) {
        ui.showModal(confirmQuickTaskModal);
        return;
      }
      const newTasks = [{ cmd: fullCmd, delay: "0" }];
      confirmQuickTaskOk.disabled = true;
      confirmQuickTaskOk.textContent = "同步中...";
      try {
        const res = await RequestApi.saveAutoTasks(JSON.stringify(newTasks));
        if (res === "OK") {
          ui.hideModal(confirmQuickTaskModal);
          ui.hideModal(autoModal);
          closeFileSheet();
          window.SKInputSimulator.replaceTasks(newTasks);
          app.openAutoSheet();
        }
      } catch (e) {
        alert("同步至服务器失败，请检查网络");
      } finally {
        confirmQuickTaskOk.disabled = false;
        confirmQuickTaskOk.textContent = "确定覆盖";
      }
    }
  }

  async function copyPreparedFileAndContinue() {
    if (!pendingPreparedFile || !pendingPreparedFile.needsCopy) return;
    const srcFile = pendingPreparedFile.sourceFile;
    const dstFile = pendingPreparedFile.resolvedFile;
    const copyCmd = `cp -f ${window.SKTerminalCore.shellQuote(srcFile)} ${window.SKTerminalCore.shellQuote(dstFile)}`;
    execMountConfirm.disabled = true;
    execMountConfirm.textContent = "拷贝中...";
    try {
      await executeImmediateCommand(copyCmd);
      const adbMountState = await RequestApi.checkExecMount(window.SKTerminalCore.getPathDir(dstFile));
      if (pendingPreparedFile.fileType !== "shell_script" && adbMountState !== "can exec") {
        throw new Error("拷贝完成，但隐藏目录仍然不可执行，请检查系统环境");
      }
      pendingPreparedFile = {
        ...pendingPreparedFile,
        needsCopy: false,
      };
      ui.hideModal(execMountModal);
      showPreparedModal();
    } catch (e) {
      alert(e.message || "拷贝失败，请稍后重试");
    } finally {
      execMountConfirm.disabled = false;
      execMountConfirm.textContent = "一键拷贝并继续";
    }
  }

  pathInput.onclick = () => {
    pathInput.readOnly = false;
    pathInput.focus();
    pathGo.style.display = "flex";
  };

  pathGo.onclick = () => loadDir(pathInput.value.trim() || currentPath);
  fileNewFolder.onclick = openMkdirModal;
  fileBack.onclick = () => loadDir(ui.dirname(currentPath));
  fileRefresh.onclick = () => loadDir(currentPath);
  pasteCancel.onclick = clearClipboard;
  pasteConfirm.onclick = () => pasteClipboard();

  fileList.addEventListener("pointerdown", (e) => {
    const row = e.target.closest('.file-row');
    if (!row || row.dataset.isdir !== "true") return;
    longPressHandled = false;
    touchMoved = false;
    longPressStartX = e.clientX;
    longPressStartY = e.clientY;
    clearTimeout(longPressTimer);
    longPressTimer = setTimeout(() => {
      if (touchMoved) return;
      longPressHandled = true;
      longPressHandledAt = Date.now();
      openActionMenu(buildItem(row.dataset.path, true));
    }, 550);
  });

  fileList.addEventListener("pointermove", (e) => {
    const dx = Math.abs(e.clientX - longPressStartX);
    const dy = Math.abs(e.clientY - longPressStartY);
    if (dx < 8 && dy < 8) return;
    touchMoved = true;
    clearTimeout(longPressTimer);
  });

  ["pointerup", "pointercancel", "pointerleave"].forEach(eventName => {
    fileList.addEventListener(eventName, () => {
      clearTimeout(longPressTimer);
    });
  });

  fileList.onclick = (e) => {
    const row = e.target.closest('.file-row');
    if (!row) return;
    const path = row.dataset.path;
    const isDir = row.dataset.isdir === "true";

    if (isDir) {
      if (longPressHandled && Date.now() - longPressHandledAt < 900) {
        longPressHandled = false;
        return;
      }
      longPressHandled = false;
      loadDir(path);
    } else {
      openActionMenu(buildItem(path, false));
    }
  };

  fileList.oncontextmenu = (e) => {
    const row = e.target.closest('.file-row');
    if (!row) return;
    e.preventDefault();
    clearTimeout(longPressTimer);
    longPressHandled = true;
    longPressHandledAt = Date.now();
    openActionMenu(buildItem(row.dataset.path, row.dataset.isdir === "true"));
  };

  fileBtn.onclick = openFileSheet;
  fileClose.onclick = closeFileSheet;

  actionCancel.onclick = () => ui.hideModal(actionModal);
  actExec.onclick = () => prepareAndOpenFlow("exec");
  actAuto.onclick = () => prepareAndOpenFlow("simulator");
  actCopy.onclick = () => setClipboard("copy");
  actCut.onclick = () => setClipboard("move");
  actRename.onclick = openRenameModal;
  actDelete.onclick = openDeleteModal;

  execCancel.onclick = () => ui.hideModal(execModal);
  execConfirm.onclick = async () => {
    await submitPreparedCommand();
  };

  autoCancel.onclick = () => ui.hideModal(autoModal);
  autoConfirm.onclick = async () => {
    await submitPreparedCommand();
  };

  confirmQuickTaskCancel.onclick = () => ui.hideModal(confirmQuickTaskModal);
  confirmQuickTaskOk.onclick = () => submitPreparedCommand({ skipConfirm: true });

  execMountCancel.onclick = () => {
    ui.hideModal(execMountModal);
    clearPendingPreparedFile();
  };
  execMountConfirm.onclick = () => copyPreparedFileAndContinue();

  renameCancel.onclick = () => ui.hideModal(renameModal);
  renameConfirm.onclick = () => {
    if (!currentItem) return;
    const newName = validateName(renameInput.value, "新名称");
    if (!newName) return;
    if (newName === currentItem.name) {
      alert("新名称不能和原名称相同");
      return;
    }
    if (targetExists(newName)) {
      alert("同目录已存在同名项目，请换一个名称");
      return;
    }

    const dir = ui.dirname(currentItem.path);
    const newPath = ui.joinPath(dir, newName);
    const finalCmd = `mv ${window.SKTerminalCore.shellQuote(currentItem.path)} ${window.SKTerminalCore.shellQuote(newPath)}`;

    ui.hideModal(renameModal);
    executeImmediateCommand(finalCmd);
  };

  deleteCancel.onclick = () => ui.hideModal(deleteModal);
  deleteConfirm.onclick = () => {
    if (!currentItem) return;
    const finalCmd = `rm -rf ${window.SKTerminalCore.shellQuote(currentItem.path)}`;
    
    ui.hideModal(deleteModal);
    executeImmediateCommand(finalCmd);
  };

  mkdirCancel.onclick = () => ui.hideModal(mkdirModal);
  mkdirConfirm.onclick = () => {
    const folderName = validateName(mkdirInput.value, "文件夹名称");
    if (!folderName) return;
    if (targetExists(folderName)) {
      alert("当前目录已存在同名项目，请换一个名称");
      return;
    }
    const finalCmd = `mkdir ${window.SKTerminalCore.shellQuote(ui.joinPath(currentPath, folderName))}`;
    ui.hideModal(mkdirModal);
    executeImmediateCommand(finalCmd);
  };

  pasteConflictCancel.onclick = () => {
    pendingPasteCommand = "";
    ui.hideModal(pasteConflictModal);
  };
  pasteConflictConfirm.onclick = () => {
    if (!pendingPasteCommand) return;
    executePasteCommand(pendingPasteCommand);
  };

  window.SKFileManager = {
    open: openFileSheet,
    close: closeFileSheet,
    loadDir,
  };

  const prevCloseAllSheets = app.closeAllSheets;
  app.closeAllSheets = () => {
    if (typeof prevCloseAllSheets === 'function') prevCloseAllSheets();
    closeFileSheet();
  };
})();
