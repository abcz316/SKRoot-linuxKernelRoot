(() => {
  const out = document.getElementById("out");
  const cmd = document.getElementById("cmd");
  const sendBtn = document.getElementById("sendBtn");
  const connDot = document.getElementById("connDot");
  const connText = document.getElementById("connText");
  const quickActions = document.getElementById("quickActions");
  const fileBtn = document.getElementById("fileBtn");
  const autoBtn = document.getElementById("autoBtn");
  const sheetOverlay = document.getElementById("sheetOverlay");
  const pageExitOverlay = document.getElementById("pageExitOverlay");
  const terminalKeepSwitch = document.getElementById("terminalKeepSwitch");
  const terminalRestartBtn = document.getElementById("terminalRestartBtn");
  const transportRadios = document.querySelectorAll('input[name="terminalTransport"]');

  const terminalCore = window.SKTerminalCore?.createTerminalCore({
    out,
    connDot,
    connText,
  });

  if (!terminalCore) {
    console.error("SKTerminalCore not loaded");
    return;
  }

  async function refreshHistory() {
    let history = await RequestApi.getQuickActions();
    if (!history || !Array.isArray(history) || history.length === 0) history = [];
    quickActions.innerHTML = history.reverse().map(cmdStr => {
      const displayStr = cmdStr.length > 17 ? cmdStr.substring(0, 17) + '...' : cmdStr;
      return `<div class="action-chip" data-cmd="${cmdStr}" title="${cmdStr}">${displayStr}</div>`;
    }).join('');
  }

  async function sendCommand() {
    const raw = cmd.value || "";
    const v = raw.trim();
    cmd.value = "";
    cmd.focus();
    sendBtn.disabled = true;
    try {
      await RequestApi.sendCommand(v);
      setTimeout(refreshHistory, 300);
    } catch (e) {
      terminalCore.appendLine("ERR: 发送失败 - " + (e && e.message ? e.message : String(e)));
    } finally {
      sendBtn.disabled = false;
      terminalCore.scrollBottom();
    }
  }
  
  const app = {
    elements: {
      out,
      cmd,
      sendBtn,
      connDot,
      connText,
      quickActions,
      fileBtn,
      autoBtn,
      sheetOverlay,
      pageExitOverlay,
    },
    refreshHistory,
    sendCommand,
    appendLine: terminalCore.appendLine,
    setConn: terminalCore.setConn,
    scrollBottom: terminalCore.scrollBottom,
    formatOutputText: terminalCore.formatOutputText,
    consumeChunk: terminalCore.consumeChunk,
    closeAllSheets: null,
    openAutoSheet: null,
    effectiveTerminalKeepMode: false,
    savedTerminalKeepMode: false,
  };

  async function initTerminalSettings() {
    if (!terminalKeepSwitch) return;
    try {
      const terminalKeepMode = await RequestApi.getTerminalKeepMode() == "1";
      app.effectiveTerminalKeepMode = terminalKeepMode;
      app.savedTerminalKeepMode = terminalKeepMode;
      terminalKeepSwitch.checked = terminalKeepMode;
    } catch (e) {
      console.warn("load terminal settings failed:", e);
    }

    terminalKeepSwitch.addEventListener("change", async () => {
      const nextValue = terminalKeepSwitch.checked;
      terminalKeepSwitch.disabled = true;
      try {
        await RequestApi.saveTerminalKeepMode(nextValue);
        app.savedTerminalKeepMode = nextValue;
        window.SKUiUtils?.showToast?.("设置已保存，重启模块后生效", 1800);
      } catch (e) {
        terminalKeepSwitch.checked = app.savedTerminalKeepMode;
        window.SKUiUtils?.showToast?.("设置保存失败，请稍后重试", 1800);
        console.warn("save terminal settings failed:", e);
      } finally {
        terminalKeepSwitch.disabled = false;
      }
    });
  }

  async function initTerminalTransportMode() {
    if (!transportRadios.length) return;
    let savedMode = "pty";

    function setRadioChecked(mode, disabled) {
      transportRadios.forEach(radio => {
        if (radio.value === mode) radio.checked = true;
        radio.disabled = !!disabled;
      });
    }

    try {
      const mode = await RequestApi.getTerminalTransportMode();
      if (mode === "pipe" || mode === "pty") savedMode = mode;
      setRadioChecked(savedMode, false);
    } catch (e) {
      console.warn("load terminal transport mode failed:", e);
    }

    transportRadios.forEach(radio => {
      radio.addEventListener("change", async () => {
        if (!radio.checked) return;
        const nextMode = radio.value;
        setRadioChecked(nextMode, true);
        try {
          await RequestApi.saveTerminalTransportMode(nextMode);
          savedMode = nextMode;
          window.SKUiUtils?.showToast?.("设置已保存，重启模块后生效", 1800);
        } catch (e) {
          setRadioChecked(savedMode, false);
          window.SKUiUtils?.showToast?.("设置保存失败，请稍后重试", 1800);
          console.warn("save terminal transport mode failed:", e);
        } finally {
          setRadioChecked(savedMode, false);
        }
      });
    });
  }

  async function initTerminalRestartBtn() {
    if (!terminalRestartBtn) return;
    terminalRestartBtn.addEventListener("click", async () => {
      terminalRestartBtn.disabled = true;
      const oldText = terminalRestartBtn.textContent;
      terminalRestartBtn.textContent = "正在重启…";
      try {
        await RequestApi.restartModule();
        out.innerHTML = "";
        terminalCore.scrollBottom?.();
        window.SKUiUtils?.showToast?.("模块已重启，当前模式已生效", 1800);
      } catch (e) {
        window.SKUiUtils?.showToast?.("重启失败，请稍后重试", 1800);
        console.warn("restart module failed:", e);
      } finally {
        terminalRestartBtn.disabled = false;
        terminalRestartBtn.textContent = oldText;
      }
    });
  }

  window.SKRootApp = app;

  quickActions.addEventListener("click", (e) => {
    const chip = e.target.closest(".action-chip");
    if (chip && chip.dataset.cmd) {
      cmd.value = chip.dataset.cmd;
      cmd.focus();
    }
  });

  cmd.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      sendCommand();
    }
  });

  sendBtn.addEventListener("click", sendCommand);
  terminalCore.setConn(null, "连接中");
  initTerminalSettings();
  initTerminalTransportMode();
  initTerminalRestartBtn();
  refreshHistory();
  cmd.focus();
  setInterval(terminalCore.tick, 1000);


  let pageExited = false;

  function showPageExitOverlay() {
    if (!pageExitOverlay) return;
    pageExitOverlay.classList.add("show");
    pageExitOverlay.setAttribute("aria-hidden", "false");
  }

  function onPageHidden() {
    if (pageExited) return;

    // 兼容后台模式在本次 WebUI 创建时就已生效；页面隐藏时不主动释放终端。
    // 开关修改只影响下次打开，所以这里不要读取 savedTerminalKeepMode。
    if (app.effectiveTerminalKeepMode) return;

    pageExited = true;

    showPageExitOverlay();
    terminalCore.setConn(false, "已退出");
    cmd.disabled = true;
    sendBtn.disabled = true;

    try {
      if (typeof app.closeAllSheets === "function") app.closeAllSheets();
    } catch (e) {
      console.warn("close sheets failed:", e);
    }

    try {
      RequestApi.exitWebui();
    } catch (e) {
      console.warn("exitWebui failed:", e);
    }
  }

  document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "hidden") onPageHidden();
  });

  window.addEventListener("pagehide", onPageHidden);

})();
