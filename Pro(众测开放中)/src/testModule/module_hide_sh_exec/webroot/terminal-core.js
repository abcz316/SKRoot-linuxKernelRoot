(() => {
  function createTerminalCore(elements) {
    const { out, connDot, connText } = elements;

    let failCount = 0;
    let pending = "";
    let partialRow = null;

    function formatOutputText(text) {
      if (!text) return "";
      let html = text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
      if (/(成功|OK|DONE)/.test(html)) return `<span class="hl-root">${html}</span>`;
      const errPattern = /(发送失败|ERR:|FAILED|Error|error|失败|HTTP [45]\d{2})/g;
      return html.replace(errPattern, (match) => `<span class="hl-err">${match}</span>`);
    }

    function scrollBottom() {
      requestAnimationFrame(() => {
        out.scrollTop = out.scrollHeight;
      });
    }

    function appendLine(text) {
      const row = document.createElement("div");
      row.className = "line";
      const txt = document.createElement("div");
      txt.className = "txt";
      txt.innerHTML = formatOutputText(text);
      row.appendChild(txt);
      out.appendChild(row);
      scrollBottom();
    }

    function setPartialText(text) {
      if (!text) {
        if (partialRow) {
          partialRow.remove();
          partialRow = null;
        }
        return;
      }
      if (!partialRow) {
        partialRow = document.createElement("div");
        partialRow.className = "line";
        partialRow.innerHTML = '<div class="txt"></div>';
        out.appendChild(partialRow);
      }
      partialRow.firstChild.innerHTML = formatOutputText(text);
      scrollBottom();
    }

    function normalizePtyOutput(s) {
      return String(s ?? "")
        .replace(/\r\n/g, "\n")
        .replace(/\r/g, "");
    }

    function consumeChunk(chunk) {
      if (!chunk) return;
      pending += normalizePtyOutput(chunk);
      const parts = pending.split("\n");
      pending = parts.pop();
      for (const line of parts) {
        appendLine(line);
      }
      setPartialText(pending);
    }

    function setConn(ok, text) {
      connDot.classList.remove("ok", "bad", "connecting");
      if (ok === true) connDot.classList.add("ok");
      else if (ok === false) connDot.classList.add("bad");
      else connDot.classList.add("connecting");
      connText.textContent = text;
    }

	let hasConnectedOnce = false;
	let exitOverlayShown = false;

	function showPageExitOverlay() {
	  if (exitOverlayShown) return;
	  exitOverlayShown = true;
	  const overlay = document.getElementById("pageExitOverlay");
	  if (overlay) overlay.classList.add("show");
	}

	async function tick() {
	  try {
		const chunk = await RequestApi.getNewOutput();
		if (chunk) consumeChunk(chunk);
		failCount = 0;
		hasConnectedOnce = true;
		setConn(true, "在线");
	  } catch (e) {
		failCount++;
		if (!hasConnectedOnce) {
		  setConn(false, "异常");
		  return;
		}
		if (failCount >= 2) {
		  setConn(false, "已退出");
		  showPageExitOverlay();
		  return;
		}
		setConn(null, "连接中");
	  }
	}

    return {
      formatOutputText,
      scrollBottom,
      appendLine,
      consumeChunk,
      setConn,
      tick,
    };
  }

  function shellQuote(s) {
    s = String(s ?? "");
    return "'" + s.replace(/'/g, `'\\''`) + "'";
  }

  function splitShellArgs(input) {
    input = String(input ?? "").trim();
    if (!input) return [];
    const args = [];
    let cur = "";
    let quote = null; // "'" or '"'
    let escape = false;
    for (let i = 0; i < input.length; i++) {
      const ch = input[i];
      if (escape) {
        cur += ch;
        escape = false;
        continue;
      }
      if (quote === '"') {
        if (ch === "\\") escape = true;
        else if (ch === '"') quote = null;
        else cur += ch;
        continue;
      }
      if (quote === "'") {
        if (ch === "'") quote = null;
        else cur += ch;
        continue;
      }
      // 不在引号内
      if (/\s/.test(ch)) {
        if (cur) { args.push(cur); cur = ""; }
        continue;
      }
      if (ch === '"' || ch === "'") { quote = ch; continue; }
      if (ch === "\\") { escape = true; continue; }
      cur += ch;
    }
    if (escape) cur += "\\";
    if (quote) throw new Error("参数引号未闭合");
    if (cur) args.push(cur);
    return args;
  }

  function getPathDir(filePath) {
    const p = String(filePath ?? "");
    const idx = p.lastIndexOf("/");
    if (idx < 0) return ".";
    if (idx === 0) return "/";
    return p.slice(0, idx);
  }

  function buildShCommand(filePath, rawArgs) {
    filePath = String(filePath ?? "");
    const dir = getPathDir(filePath);
    const argv = splitShellArgs(rawArgs).map(shellQuote);
    const cmd = ["(cd", shellQuote(dir), "&&", "sh", shellQuote(filePath), ...argv,].join(" ");
    return cmd + ")";
  }

  function buildExecCommand(filePath, rawArgs) {
    filePath = String(filePath ?? "");
    const dir = getPathDir(filePath);
    const argv = splitShellArgs(rawArgs).map(shellQuote);
    const quotedFile = shellQuote(filePath);
    const cmd = ["(cd", shellQuote(dir), "&&", "chmod", "777", quotedFile, "&&", quotedFile, ...argv].join(" ");
    return cmd + ")";
  }

  window.SKTerminalCore = {
    createTerminalCore,
    shellQuote,
    buildShCommand,
    buildExecCommand,
    getPathDir,
  };
})();
