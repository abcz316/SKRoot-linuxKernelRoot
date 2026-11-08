(() => {
  function create({ model, api, render, normalizeEntry, invalidatePane }) {
    const intents = { left: 0, right: 0 };
    const findPane = archive => ['left', 'right'].find(p => model.panes[p].archive === archive);
    const active = archive => !!archive && !archive.closed && !!findPane(archive);
    function paint(archive) { const pane = findPane(archive); if (pane) render(pane); }

    async function release(pane) {
      const archive = model.leaveArchive(pane);
      if (!archive) return;
      archive.closed = true;
      clearTimeout(archive.timer);
      model.panes[pane].entries = [];
      model.panes[pane].loading = true;
      model.panes[pane].error = '';
      render(pane);
      if (archive.sessionId) await api.closeArchive(archive.sessionId).catch(() => {});
    }

    async function leave(pane) { ++intents[pane]; return release(pane); }

    async function list(archive, innerPath, offset = 0) {
      if (!active(archive)) return;
      innerPath ??= archive.innerPath;
      const pane = findPane(archive);
      const sequence = ++archive.sequence;
      if (innerPath !== archive.innerPath && model.selectionPane === pane) model.clearSelection();
      archive.innerPath = innerPath;
      archive.offset = offset;
      model.panes[pane].loading = true;
      model.panes[pane].error = '';
      paint(archive);
      try {
        const result = await api.listArchive(archive.sessionId, innerPath, offset, 500);
        if (!active(archive) || sequence !== archive.sequence) return;
        const state = model.panes[findPane(archive)];
        archive.total = Number(result.total) || 0;
        state.entries = result.items.map(normalizeEntry);
        state.scrollTop = 0;
        state.loading = false;
      } catch (error) {
        if (!active(archive) || sequence !== archive.sequence) return;
        const state = model.panes[findPane(archive)];
        state.loading = false;
        state.error = error?.code === 'ARCHIVE_CHANGED' ? '压缩包已改变，请刷新重新打开' : error?.message || '无法读取压缩包';
        state.entries = [];
      }
      paint(archive);
    }

    async function poll(archive) {
      if (!active(archive)) return;
      try {
        const status = await api.getArchiveStatus(archive.sessionId);
        if (!active(archive)) return;
        archive.phase = status.state;
        archive.scanned = Number(status.scannedEntries) || 0;
        if (status.state === 'ready') return list(archive);
        if (['failed', 'cancelled'].includes(status.state)) throw new Error(status.error?.message || status.message || '压缩包索引失败');
        paint(archive);
        archive.timer = setTimeout(() => poll(archive), 300);
      } catch (error) {
        if (!active(archive)) return;
        const state = model.panes[findPane(archive)];
        state.loading = false;
        state.error = error?.message || '无法打开压缩包';
        paint(archive);
      }
    }

    async function open(pane, path) {
      const intent = ++intents[pane];
      invalidatePane(pane);
      await release(pane);
      if (intent !== intents[pane]) return;
      const archive = { sessionId: '', archivePath: path, innerPath: '', offset: 0,
        total: 0, phase: 'queued', scanned: 0, sequence: 0, closed: false, timer: null };
      model.enterArchive(pane, archive);
      model.panes[pane].loading = true;
      paint(archive);
      try {
        const result = await api.openArchive(path);
        archive.sessionId = result.sessionId;
        if (!active(archive)) { await api.closeArchive(result.sessionId).catch(() => {}); return; }
        await poll(archive);
      } catch (error) {
        if (!active(archive)) return;
        const state = model.panes[findPane(archive)];
        state.loading = false;
        state.error = error?.message || '无法打开压缩包';
        paint(archive);
      }
    }

    return {
      open, leave,
      navigate(pane, path) { return list(model.panes[pane].archive, path, 0); },
      page(pane, offset) { return list(model.panes[pane].archive, undefined, offset); },
      async resume(pane) {
        const archive = model.panes[pane].archive;
        if (!archive || archive.closed) return;
        if (archive.phase === 'ready') await list(archive, archive.innerPath, archive.offset);
        else await open(pane, archive.archivePath);
      },
      refresh(pane) { const archive = model.panes[pane].archive; return archive && open(pane, archive.archivePath); },
      async close() { await Promise.all(['left', 'right'].map(leave)); },
    };
  }
  window.SKArchiveBrowser = { create };
})();
