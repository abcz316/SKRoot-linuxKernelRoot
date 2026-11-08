(function (root, factory) {
  const exported = factory();
  if (typeof module === "object" && module.exports) module.exports = exported;
  else root.SKImageViewer = exported;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const MAX_FILE_BYTES = 32 * 1024 * 1024;
  const MAX_PIXELS = 32000000;
  const CHUNK_BYTES = 128 * 1024;
  const IMAGE_MIMES = new Set(["image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"]);

  function isImageName(name) {
    return /\.(?:png|jpe?g|gif|webp|bmp)$/i.test(String(name || ""));
  }

  function fitScale(width, height, viewportWidth, viewportHeight) {
    if (!(width > 0 && height > 0 && viewportWidth > 0 && viewportHeight > 0)) return 1;
    return Math.min(1, viewportWidth / width, viewportHeight / height);
  }

  function clampPosition(x, y, scale, width, height, viewportWidth, viewportHeight) {
    const maxX = Math.max(0, (width * scale - viewportWidth) / 2);
    const maxY = Math.max(0, (height * scale - viewportHeight) / 2);
    return { x: Math.max(-maxX, Math.min(maxX, x)), y: Math.max(-maxY, Math.min(maxY, y)) };
  }

  function validateOpened(opened) {
    return typeof opened?.sessionId === "string" && !!opened.sessionId
      && Number.isSafeInteger(opened.size) && opened.size > 0 && opened.size <= MAX_FILE_BYTES
      && Number.isInteger(opened.width) && opened.width > 0 && opened.width <= 32768
      && Number.isInteger(opened.height) && opened.height > 0 && opened.height <= 32768
      && opened.width * opened.height <= MAX_PIXELS && IMAGE_MIMES.has(opened.mime);
  }

  function decodeChunk(chunk, offset, size) {
    if (chunk?.offset !== offset || typeof chunk.base64 !== "string"
        || chunk.base64.length > Math.ceil(CHUNK_BYTES / 3) * 4) throw new Error("图片读取响应无效");
    const text = atob(chunk.base64);
    const bytes = Uint8Array.from(text, ch => ch.charCodeAt(0));
    const next = offset + bytes.length;
    if (!bytes.length || bytes.length > CHUNK_BYTES || next > size || chunk.nextOffset !== next
        || typeof chunk.eof !== "boolean" || chunk.eof !== (next === size)) {
      throw new Error("图片读取进度无效，请重新打开");
    }
    return bytes;
  }

  function create({ root, api } = {}) {
    if (!api) throw new Error("Image viewer requires a file API");
    const element = root || document.createElement("div");
    if (!root) document.body.appendChild(element);
    element.classList.add("image-viewer");
    element.hidden = true;
    element.setAttribute("role", "dialog");
    element.setAttribute("aria-modal", "true");
    element.setAttribute("aria-label", "图片查看器");
    element.innerHTML = `
      <header class="image-viewer-head">
        <button class="image-viewer-close" type="button" title="关闭图片" aria-label="关闭图片">×</button>
        <div class="image-viewer-title"><div class="image-viewer-path"></div><div class="image-viewer-meta" aria-live="polite"></div></div>
      </header>
      <div class="image-viewer-viewport" tabindex="0" aria-label="图片预览，可拖动和缩放">
        <img class="image-viewer-image" alt="" draggable="false" hidden>
        <div class="image-viewer-message" role="status"></div>
      </div>
      <footer class="image-viewer-tools" role="group" aria-label="图片缩放">
        <button type="button" data-image-action="fit">适应</button>
        <button type="button" data-image-action="actual">100%</button>
        <button type="button" data-image-action="out" title="缩小" aria-label="缩小">−</button>
        <output class="image-viewer-scale" aria-label="缩放比例">—</output>
        <button type="button" data-image-action="in" title="放大" aria-label="放大">+</button>
      </footer>`;
    const image = element.querySelector(".image-viewer-image");
    const viewport = element.querySelector(".image-viewer-viewport");
    const pathLabel = element.querySelector(".image-viewer-path");
    const metadata = element.querySelector(".image-viewer-meta");
    const message = element.querySelector(".image-viewer-message");
    const scaleLabel = element.querySelector(".image-viewer-scale");
    const buttons = Array.from(element.querySelectorAll("[data-image-action]"));
    const closeButton = element.querySelector(".image-viewer-close");
    let generation = 0;
    let active = null;
    let returnFocus = null;
    let width = 0, height = 0, scale = 1, x = 0, y = 0, fitting = true;
    let pinch = null;
    const pointers = new Map();

    const live = state => active === state && state.generation === generation && !element.hidden;
    const releaseSession = id => {
      if (id) Promise.resolve().then(() => api.closeImage(id)).catch(() => {});
    };
    const clearUrl = state => {
      if (state?.url) {
        URL.revokeObjectURL(state.url);
        state.url = "";
      }
    };

    function viewportSize() {
      return { width: viewport.clientWidth, height: viewport.clientHeight };
    }

    function renderTransform() {
      if (!width || !height) return;
      const size = viewportSize();
      ({ x, y } = clampPosition(x, y, scale, width, height, size.width, size.height));
      image.style.transform = `translate(-50%, -50%) translate(${x}px, ${y}px) scale(${scale})`;
      scaleLabel.textContent = `${Math.round(scale * 100)}%`;
    }

    function fit() {
      if (!width || !height) return;
      const size = viewportSize();
      scale = fitScale(width, height, size.width, size.height);
      x = y = 0;
      fitting = true;
      renderTransform();
    }

    function zoom(next, anchorX = 0, anchorY = 0) {
      if (!width || !height || !active?.ready) return;
      const size = viewportSize();
      const minimum = Math.min(0.05, fitScale(width, height, size.width, size.height));
      const bounded = Math.max(minimum, Math.min(8, next));
      const ratio = bounded / scale;
      x = anchorX - (anchorX - x) * ratio;
      y = anchorY - (anchorY - y) * ratio;
      scale = bounded;
      fitting = false;
      renderTransform();
    }

    function close() {
      ++generation;
      const old = active;
      active = null;
      old?.controller.abort();
      old?.cancelDecode?.();
      releaseSession(old?.sessionId);
      image.onload = image.onerror = null;
      image.removeAttribute("src");
      image.hidden = true;
      clearUrl(old);
      element.hidden = true;
      element.setAttribute("aria-hidden", "true");
      pointers.clear();
      pinch = null;
      width = height = 0;
      scaleLabel.textContent = "—";
      if (returnFocus?.isConnected) window.SKUiUtils?.focusWithoutKeyboard(returnFocus);
      returnFocus = null;
    }

    async function open(item) {
      close();
      returnFocus = document.activeElement;
      const state = { generation, controller: new AbortController(), sessionId: "", url: "", ready: false, cancelDecode: null };
      active = state;
      element.hidden = false;
      element.setAttribute("aria-hidden", "false");
      pathLabel.textContent = String(item?.path || "");
      pathLabel.title = pathLabel.textContent;
      metadata.textContent = "正在读取";
      metadata.dataset.state = "loading";
      message.textContent = "正在读取图片…";
      message.hidden = false;
      image.hidden = true;
      buttons.forEach(button => { button.disabled = true; });
      closeButton.focus({ preventScroll: true });
      try {
        // Do not abort open: its response contains the ID that must be closed if
        // the viewer was dismissed while the server was creating the session.
        const opened = await api.openImage(String(item?.path || ""));
        state.sessionId = opened?.sessionId || "";
        if (!live(state)) { releaseSession(state.sessionId); return; }
        if (!validateOpened(opened)) throw new Error("图片信息无效或超出预览限制");
        const chunks = [];
        let offset = 0;
        while (offset < opened.size) {
          const chunk = await api.readImageChunk(state.sessionId, offset, CHUNK_BYTES, { signal: state.controller.signal });
          if (!live(state)) return;
          chunks.push(decodeChunk(chunk, offset, opened.size));
          offset = chunk.nextOffset;
          message.textContent = `正在读取图片 ${Math.round(offset / opened.size * 100)}%`;
        }
        releaseSession(state.sessionId);
        state.sessionId = "";
        const blob = new Blob(chunks, { type: opened.mime });
        chunks.length = 0;
        state.url = URL.createObjectURL(blob);
        message.textContent = "正在显示图片…";
        await new Promise((resolve, reject) => {
          state.cancelDecode = () => reject(new DOMException("Preview closed", "AbortError"));
          image.onload = () => resolve();
          image.onerror = () => reject(new Error("图片已损坏或当前 WebView 不支持此图片"));
          image.src = state.url;
        });
        state.cancelDecode = null;
        if (!live(state)) { clearUrl(state); return; }
        image.onload = image.onerror = null;
        width = image.naturalWidth;
        height = image.naturalHeight;
        if (!(width > 0 && height > 0) || width > 32768 || height > 32768 || width * height > MAX_PIXELS)
          throw new Error("图片解码尺寸超出预览限制");
        image.style.width = `${width}px`;
        image.style.height = `${height}px`;
        image.alt = item?.name || String(item?.path || "").split("/").pop() || "图片";
        metadata.textContent = `${width} × ${height} · ${(opened.size / (1024 * 1024)).toFixed(2)} MiB`;
        metadata.dataset.state = "ready";
        image.hidden = false;
        message.hidden = true;
        state.ready = true;
        buttons.forEach(button => { button.disabled = false; });
        fit();
      } catch (error) {
        releaseSession(state.sessionId);
        state.sessionId = "";
        if (!live(state)) { clearUrl(state); return; }
        image.onload = image.onerror = null;
        image.removeAttribute("src");
        clearUrl(state);
        state.cancelDecode = null;
        message.textContent = error?.message || "无法打开图片";
        message.hidden = false;
        metadata.textContent = "无法预览";
        metadata.dataset.state = "error";
      }
    }

    closeButton.onclick = close;
    buttons.forEach(button => {
      button.onclick = () => {
        const action = button.dataset.imageAction;
        if (action === "fit") fit();
        else if (action === "actual") { x = y = 0; zoom(1); }
        else zoom(scale * (action === "in" ? 1.25 : 0.8));
      };
    });
    element.addEventListener("keydown", event => {
      if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); close(); }
      else if (event.key === "+" || event.key === "=") { event.preventDefault(); zoom(scale * 1.25); }
      else if (event.key === "-") { event.preventDefault(); zoom(scale * 0.8); }
      else if (event.key === "0") { event.preventDefault(); fit(); }
      else if (event.key === "Tab") {
        const focusable = [closeButton, viewport, ...buttons.filter(button => !button.disabled)];
        const current = focusable.indexOf(document.activeElement);
        const next = (current + (event.shiftKey ? -1 : 1) + focusable.length) % focusable.length;
        event.preventDefault();
        focusable[next].focus();
      }
    });
    viewport.addEventListener("wheel", event => {
      if (!active?.ready) return;
      event.preventDefault();
      const rect = viewport.getBoundingClientRect();
      zoom(scale * Math.exp(-event.deltaY * 0.002), event.clientX - rect.left - rect.width / 2,
        event.clientY - rect.top - rect.height / 2);
    }, { passive: false });

    function pinchSnapshot() {
      if (pointers.size < 2) return null;
      const [a, b] = Array.from(pointers.values());
      return { distance: Math.hypot(b.x - a.x, b.y - a.y), x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    }

    viewport.addEventListener("pointerdown", event => {
      if (!active?.ready || (event.pointerType === "mouse" && event.button !== 0)) return;
      event.preventDefault();
      pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
      viewport.setPointerCapture(event.pointerId);
      pinch = pinchSnapshot();
    });
    viewport.addEventListener("pointermove", event => {
      const previous = pointers.get(event.pointerId);
      if (!previous || !active?.ready) return;
      event.preventDefault();
      pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
      if (pointers.size === 1) {
        x += event.clientX - previous.x;
        y += event.clientY - previous.y;
        fitting = false;
        renderTransform();
      } else {
        const next = pinchSnapshot();
        if (pinch?.distance > 0 && next?.distance > 0) {
          const rect = viewport.getBoundingClientRect();
          zoom(scale * next.distance / pinch.distance, pinch.x - rect.left - rect.width / 2,
            pinch.y - rect.top - rect.height / 2);
          x += next.x - pinch.x;
          y += next.y - pinch.y;
          renderTransform();
        }
        pinch = next;
      }
    });
    const endPointer = event => { pointers.delete(event.pointerId); pinch = pinchSnapshot(); };
    viewport.addEventListener("pointerup", endPointer);
    viewport.addEventListener("pointercancel", endPointer);
    viewport.addEventListener("lostpointercapture", endPointer);
    viewport.addEventListener("dblclick", event => { event.preventDefault(); if (fitting) zoom(1); else fit(); });
    const resized = () => { if (active?.ready) { if (fitting) fit(); else renderTransform(); } };
    if (typeof ResizeObserver === "function") new ResizeObserver(resized).observe(viewport);
    else window.addEventListener("resize", resized);
    window.addEventListener("pagehide", close);
    return { open, close, get isOpen() { return !element.hidden; } };
  }

  return { create, isImageName, fitScale, clampPosition, validateOpened, decodeChunk };
});
