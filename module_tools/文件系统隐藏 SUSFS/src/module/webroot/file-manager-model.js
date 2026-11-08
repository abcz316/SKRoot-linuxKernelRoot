(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.SKFileManagerModel = api;
})(typeof globalThis !== "undefined" ? globalThis : this, () => {
  function normalizePath(value) {
    const raw = String(value || "/").replace(/\/+/g, "/");
    const parts = [];
    for (const part of raw.split("/")) {
      if (!part || part === ".") continue;
      if (part === "..") parts.pop();
      else parts.push(part);
    }
    return "/" + parts.join("/");
  }

  function joinPath(base, name) {
    const parent = normalizePath(base);
    return normalizePath(`${parent === "/" ? "" : parent}/${String(name || "")}`);
  }

  function parentPath(path) {
    const normalized = normalizePath(path);
    if (normalized === "/") return "/";
    const parts = normalized.split("/");
    parts.pop();
    return parts.join("/") || "/";
  }

  function defaultZipName(paths) {
    const first = (Array.isArray(paths) ? paths : []).map(normalizePath).sort()[0] || "/archive";
    const name = first.split("/").pop() || "archive";
    const stem = name.toLowerCase().endsWith(".zip") ? name.slice(0, -4) : name;
    return `${stem || "archive"}.zip`;
  }

  function symbolicMode(mode) {
    const value = Number(mode) & 0o7777;
    const chars = [
      value & 0o400 ? "r" : "-", value & 0o200 ? "w" : "-", value & 0o100 ? "x" : "-",
      value & 0o040 ? "r" : "-", value & 0o020 ? "w" : "-", value & 0o010 ? "x" : "-",
      value & 0o004 ? "r" : "-", value & 0o002 ? "w" : "-", value & 0o001 ? "x" : "-",
    ];
    if (value & 0o4000) chars[2] = value & 0o100 ? "s" : "S";
    if (value & 0o2000) chars[5] = value & 0o010 ? "s" : "S";
    if (value & 0o1000) chars[8] = value & 0o001 ? "t" : "T";
    return chars.join("");
  }

  function octalMode(mode) {
    return (Number(mode) & 0o7777).toString(8).padStart(4, "0");
  }

  function paneState(home = "/sdcard") {
    return {
      path: normalizePath(home),
      home: normalizePath(home),
      entries: [],
      scrollTop: 0,
      loading: false,
      error: "",
      archive: null,
    };
  }

  function normalizePlaces(entries, includeNote = false, limit = Number.POSITIVE_INFINITY) {
    const result = [];
    const seen = new Set();
    for (const item of Array.isArray(entries) ? entries : []) {
      const rawPath = typeof item === "string" ? item : item?.path;
      if (!rawPath) continue;
      const path = normalizePath(rawPath);
      if (seen.has(path)) continue;
      seen.add(path);
      const place = { path };
      if (includeNote) place.note = String(item?.note || "").trim();
      result.push(place);
      if (result.length >= limit) break;
    }
    return result;
  }

  class FileManagerModel {
    constructor(leftHome = "/sdcard", rightHome = "/sdcard") {
      this.panes = {
        left: paneState(leftHome),
        right: paneState(rightHome),
      };
      this.activePane = "left";
      this.selectionPane = null;
      this.selectedPaths = new Set();
      this.selectedArchiveItems = new Map();
      this.activeJob = null;
      this.editorSession = null;
      this.bookmarks = [];
      this.recent = [];
    }

    otherPane(pane = this.activePane) {
      return pane === "left" ? "right" : "left";
    }

    activate(pane) {
      if (pane === "left" || pane === "right") this.activePane = pane;
      return this.activePane;
    }

    setHomes(leftHome, rightHome) {
      this.panes.left.home = normalizePath(leftHome || "/sdcard");
      this.panes.right.home = normalizePath(rightHome || "/sdcard");
    }

    setHome(pane, path) {
      this.panes[pane].home = normalizePath(path);
    }

    navigate(pane, path) {
      const target = normalizePath(path);
      const state = this.panes[pane];
      state.path = target;
      state.scrollTop = 0;
      state.error = "";
      if (this.selectionPane === pane) this.clearSelection();
      return target;
    }

    setEntries(pane, entries) {
      this.panes[pane].entries = Array.isArray(entries) ? entries.slice() : [];
    }

    entryKey(pane, item) {
      const state = this.panes[pane];
      return state.archive ? item.id : joinPath(state.path, item.name);
    }

    enterArchive(pane, archive) {
      const state = this.panes[pane];
      state.archive = archive;
      state.entries = [];
      state.error = "";
      state.scrollTop = 0;
      if (this.selectionPane === pane) this.clearSelection();
    }

    leaveArchive(pane) {
      const archive = this.panes[pane].archive;
      this.panes[pane].archive = null;
      if (this.selectionPane === pane) this.clearSelection();
      return archive;
    }

    swapPanes() {
      const left = this.panes.left;
      const right = this.panes.right;
      const leftView = {
        path: left.path,
        entries: left.entries,
        scrollTop: left.scrollTop,
        loading: left.loading,
        error: left.error,
        archive: left.archive,
      };
      left.path = right.path;
      left.entries = right.entries;
      left.scrollTop = right.scrollTop;
      left.loading = right.loading;
      left.error = right.error;
      left.archive = right.archive;
      right.path = leftView.path;
      right.entries = leftView.entries;
      right.scrollTop = leftView.scrollTop;
      right.loading = leftView.loading;
      right.error = leftView.error;
      right.archive = leftView.archive;
      this.clearSelection();
    }

    syncPanesToActive() {
      const source = this.panes[this.activePane];
      if (source.archive) return false;
      const target = this.panes[this.otherPane()];
      target.path = source.path;
      target.entries = source.entries.slice();
      target.scrollTop = source.scrollTop;
      target.loading = source.loading;
      target.error = source.error;
      target.archive = null;
      this.clearSelection();
      return true;
    }

    setPlaces(bookmarks, recent) {
      this.bookmarks = normalizePlaces(bookmarks, true);
      this.recent = normalizePlaces(recent, false, 20);
    }

    placesSnapshot() {
      return {
        bookmarks: this.bookmarks.map(item => ({ path: item.path, note: item.note || "" })),
        recent: this.recent.slice(0, 20).map(item => ({ path: item.path })),
      };
    }

    touchRecent(path) {
      const normalized = normalizePath(path);
      const before = this.recent.map(item => item.path);
      this.recent = [{ path: normalized }, ...this.recent.filter(item => item.path !== normalized)].slice(0, 20);
      return before.length !== this.recent.length || before.some((value, index) => value !== this.recent[index]?.path);
    }

    removeRecent(path) {
      const normalized = normalizePath(path);
      const previous = this.recent.length;
      this.recent = this.recent.filter(item => item.path !== normalized);
      return this.recent.length !== previous;
    }

    addBookmark(path, note = "") {
      const normalized = normalizePath(path);
      if (this.bookmarks.some(item => item.path === normalized)) return false;
      this.bookmarks.unshift({ path: normalized, note: String(note || "").trim() });
      return true;
    }

    removeBookmark(path) {
      const normalized = normalizePath(path);
      const previous = this.bookmarks.length;
      this.bookmarks = this.bookmarks.filter(item => item.path !== normalized);
      return this.bookmarks.length !== previous;
    }

    updateBookmarkNote(path, note) {
      const normalized = normalizePath(path);
      const bookmark = this.bookmarks.find(item => item.path === normalized);
      if (!bookmark) return false;
      const next = String(note || "").trim();
      if (bookmark.note === next) return false;
      bookmark.note = next;
      return true;
    }

    beginSelection(pane, path) {
      this.selectionPane = pane;
      this.activePane = pane;
      this.selectedPaths.clear();
      this.selectedArchiveItems.clear();
      if (path) {
        this.selectedPaths.add(this.panes[pane].archive ? path : normalizePath(path));
        const item = this.panes[pane].entries.find(value => value.id === path);
        if (item && this.panes[pane].archive) this.selectedArchiveItems.set(path, item);
      }
    }

    toggleSelection(pane, path) {
      const normalized = this.panes[pane].archive ? path : normalizePath(path);
      if (!this.selectionPane) this.beginSelection(pane);
      if (this.selectionPane !== pane) return false;
      if (this.selectedPaths.has(normalized)) {
        this.selectedPaths.delete(normalized);
        this.selectedArchiveItems.delete(normalized);
      }
      else {
        if (this.panes[pane].archive && this.selectedPaths.size >= 500) return false;
        this.selectedPaths.add(normalized);
        if (this.panes[pane].archive) {
          const item = this.panes[pane].entries.find(value => value.id === normalized);
          if (item) this.selectedArchiveItems.set(normalized, item);
        }
      }
      if (this.selectedPaths.size === 0) this.clearSelection();
      return true;
    }

    selectAll() {
      if (!this.selectionPane) return;
      const pane = this.panes[this.selectionPane];
      if (pane.archive) {
        const next = new Map(this.selectedArchiveItems);
        for (const item of pane.entries) if (item.selectable !== false) next.set(item.id, item);
        if (next.size > 500) return false;
        this.selectedArchiveItems = next;
        this.selectedPaths = new Set(next.keys());
        return true;
      }
      this.selectedPaths = new Set(pane.entries.map(item => this.entryKey(this.selectionPane, item)));
    }

    invertSelection() {
      if (!this.selectionPane) return;
      const pane = this.panes[this.selectionPane];
      if (pane.archive) {
        const next = new Map(this.selectedArchiveItems);
        for (const item of pane.entries) {
          if (item.selectable === false) continue;
          if (next.has(item.id)) next.delete(item.id);
          else next.set(item.id, item);
        }
        if (next.size > 500) return false;
        this.selectedArchiveItems = next;
        this.selectedPaths = new Set(next.keys());
        if (!next.size) this.clearSelection();
        return true;
      }
      const next = new Set();
      for (const item of pane.entries) {
        const path = this.entryKey(this.selectionPane, item);
        if (!this.selectedPaths.has(path)) next.add(path);
      }
      this.selectedPaths = next;
      if (next.size === 0) this.clearSelection();
    }

    clearSelection() {
      this.selectionPane = null;
      this.selectedPaths.clear();
      this.selectedArchiveItems.clear();
    }

    selectedEntries() {
      if (!this.selectionPane) return [];
      const pane = this.panes[this.selectionPane];
      if (pane.archive) return Array.from(this.selectedArchiveItems.values());
      return pane.entries.filter(item => this.selectedPaths.has(this.entryKey(this.selectionPane, item)));
    }

    operationSnapshot(operation) {
      if (!this.selectionPane || this.selectedPaths.size === 0) return null;
      const sourcePane = this.selectionPane;
      const destinationPane = this.otherPane(sourcePane);
      return {
        operation,
        sourcePane,
        destinationPane,
        sources: Array.from(this.selectedPaths),
        destination: this.panes[destinationPane].path,
      };
    }
  }

  return { FileManagerModel, normalizePath, joinPath, parentPath, defaultZipName,
    symbolicMode, octalMode, normalizePlaces };
});
