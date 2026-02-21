(() => {
  // ====== UI refs ======
  const out = document.getElementById("out");
  const cmd = document.getElementById("cmd");
  const sendBtn = document.getElementById("sendBtn");
  const connDot = document.getElementById("connDot");
  const connText = document.getElementById("connText");

  // ====== state ======
  let failCount = 0;

  // ====== stream state ======
  let pending = "";
  let partialRow = null;

  function scrollBottom() {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        out.scrollTop = out.scrollHeight;
      });
    });
  }

  function appendLine(text){
    const row = document.createElement("div");
    row.className = "line";

    const txt = document.createElement("div");
    txt.className = "txt";
    txt.textContent = text;

    row.appendChild(txt);
    out.appendChild(row);

    scrollBottom();
  }

  function ensurePartialRow(){
    if (partialRow) return partialRow;

    const row = document.createElement("div");
    row.className = "line";
    const txt = document.createElement("div");
    txt.className = "txt";
    row.appendChild(txt);
    out.appendChild(row);
    partialRow = row;

    scrollBottom();
    return partialRow;
  }

  function setPartialText(text){
    if (!text) {
      if (partialRow) {
        partialRow.remove();
        partialRow = null;
      }
      scrollBottom();
      return;
    }
    const row = ensurePartialRow();
    row.firstChild.textContent = text;
    scrollBottom();
  }

  function consumeChunk(chunk){
    if (!chunk) return;

    pending += chunk;
    const parts = pending.split("\n");
    pending = parts.pop();
    for (const line of parts) appendLine(line);
    setPartialText(pending);
  }

  function setConn(ok, text){
    connDot.classList.remove("ok", "bad", "connecting");
    if (ok === true) connDot.classList.add("ok");
    else if (ok === false) connDot.classList.add("bad");
    else connDot.classList.add("connecting");
    connText.textContent = text;
  }

  async function sendCommand(){
    const v = (cmd.value || "").trim();
    if (!v) return;

    appendLine("# " + v);

    cmd.value = "";
    cmd.focus();

    sendBtn.disabled = true;
    try {
      await RequestApi.sendCommand(v);
    } catch(e) {
      appendLine("ERR: 发送失败 - " + (e && e.message ? e.message : String(e)));
    } finally {
      sendBtn.disabled = false;
      scrollBottom();
    }
  }

	async function pollLogsOnce(){
	  const chunk = await RequestApi.getNewOutput();
	  if (chunk && chunk.length > 0) {
		consumeChunk(chunk);
		return true;
	  }
	  return false;
	}

	async function tick(){
	  try{
		await pollLogsOnce();
		failCount = 0;
		setConn(true, "在线");
	  } catch(e){
		failCount++;
		if (failCount >= 2) setConn(false, "异常");
		else setConn(null, "连接中");
	  }
	}


  // ====== events ======
  cmd.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      sendCommand();
    }
  });
  sendBtn.addEventListener("click", sendCommand);

  if (window.visualViewport) {
    const vv = window.visualViewport;
    const onVV = () => scrollBottom();
    vv.addEventListener("resize", onVV);
    vv.addEventListener("scroll", onVV);
  }
  // ====== init ======
  appendLine("#");
  setConn(null, "连接中");
  cmd.focus();
  tick();
  setInterval(tick, 1000);

})();
