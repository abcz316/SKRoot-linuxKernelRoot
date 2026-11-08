(() => {
  const icons = {
    "power": '<path d="M12 2v10M5.1 5.1a9 9 0 1 0 13.8 0"/>',
    "cloud-check": '<path d="M20 16.2A4.5 4.5 0 0 0 18 8h-1.3a7 7 0 1 0-9.7 9"/><path d="m11 17 3 3 7-7"/>',
    "cloud-upload": '<path d="M20 16.2A4.5 4.5 0 0 0 18 8h-1.3a7 7 0 1 0-9.7 9"/><path d="M14 21V11m-4 4 4-4 4 4"/>',
    "undo-2": '<path d="M3 10h12a6 6 0 0 1 0 12M3 10l5-5M3 10l5 5"/>',
    "scan": '<path d="M7 3H3v4m14-4h4v4M7 21H3v-4m14 4h4v-4M7 12h10"/>',

    "plus": '<path d="M12 5v14M5 12h14"/>',
    "eye-off": '<path d="m3 3 18 18M10.6 10.6a2 2 0 0 0 2.8 2.8M9.9 5.2A10 10 0 0 1 21 12a15 15 0 0 1-3.1 3.7M6.5 6.5A15 15 0 0 0 3 12s3.5 7 9 7a9 9 0 0 0 4.5-1.5"/>',
    "fingerprint": '<path d="M4 11a8 8 0 0 1 16 0M8 18c1-2 1-4 1-7a3 3 0 0 1 6 0c0 4-.4 7-2 10M5 15l1-4a6 6 0 0 1 12 0c0 3 0 5-1 8M11 17l1-6M5 20l1-2"/>',
    "route": '<circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><path d="M9 6h8a3 3 0 0 1 0 6H7a3 3 0 0 0 0 6h8"/>',
    "layers": '<path d="m12 3 10 6-10 6L2 9l10-6ZM2 15l10 6 10-6M2 12l10 6 10-6"/>',
    "hard-drive": '<rect x="3" y="13" width="18" height="8" rx="3"/><path d="m3 15 3-10a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2l3 10M7 17h.01M11 17h.01"/>',
    "circle-help": '<circle cx="12" cy="12" r="9"/><path d="M9 9a3 3 0 1 1 5 2c-1.5.7-2 1-2 2M12 16h.01"/>',
    "alert-circle": '<circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 17h.01"/>',

    "check": '<path d="m20 6-11 11-5-5"/>',
    "image": '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/>',
    "arrow-left": '<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>',
    "arrow-up": '<path d="m18 15-6-6-6 6"/>',
    "archive": '<path d="M3 6h18"/><path d="M5 6v14h14V6"/><path d="M3 4h18v2H3z"/><path d="M10 10h4"/>',
    "bookmark": '<path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/>',
    "bookmark-plus": '<path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/><path d="M12 7v6"/><path d="M9 10h6"/>',
    "check-square": '<polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
    "chevrons-right": '<path d="m6 17 5-5-5-5"/><path d="m13 17 5-5-5-5"/>',
    "copy": '<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
    "columns-2": '<rect width="18" height="18" x="3" y="3" rx="2"/><path d="M12 3v18"/>',
    "ellipsis-vertical": '<circle cx="12" cy="12" r="1"/><circle cx="12" cy="5" r="1"/><circle cx="12" cy="19" r="1"/>',
    "file": '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/>',
    "file-plus": '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><path d="M12 18v-6"/><path d="M9 15h6"/>',
    "file-code": '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><path d="m10 13-2 2 2 2"/><path d="m14 17 2-2-2-2"/>',
    "folder": '<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>',
    "folder-plus": '<path d="M12 10v6"/><path d="M9 13h6"/><path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>',
    "house": '<path d="m3 11 9-9 9 9"/><path d="M5 10v10h14V10"/><path d="M9 20v-6h6v6"/>',
    "history": '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l3 2"/>',
    "info": '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
    "move-right": '<path d="M18 8L22 12L18 16"/><path d="M2 12H22"/>',
    "package-plus": '<path d="m7.5 4.27 9 5.15"/><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l3-1.72"/><path d="M3.3 7 12 12l8.7-5"/><path d="M12 22V12"/><path d="M19 15v6"/><path d="M16 18h6"/>',
    "pencil": '<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
    "play": '<polygon points="5 3 19 12 5 21 5 3"/>',
    "refresh-cw": '<path d="M21 12a9 9 0 0 0-15-6.7L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 15 6.7L21 16"/><path d="M16 16h5v5"/>',
    "save": '<path d="M15.2 3a2 2 0 0 1 1.4.6l3.8 3.8a2 2 0 0 1 .6 1.4V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M17 21v-8H7v8"/><path d="M7 3v5h8"/>',
    "scissors": '<circle cx="6" cy="6" r="3"/><path d="M8.12 8.12 12 12"/><path d="M20 4 8.12 15.88"/><circle cx="6" cy="18" r="3"/><path d="M14.8 14.8 20 20"/>',
    "settings": '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.38a2 2 0 0 0-.73-2.73l-.15-.09a2 2 0 0 1-1-1.74v-.51a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
    "shield": '<path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V5l8-3 8 3z"/>',
    "square": '<rect width="18" height="18" x="3" y="3" rx="2"/>',
    "square-dashed": '<path d="M5 3a2 2 0 0 0-2 2"/><path d="M19 3a2 2 0 0 1 2 2"/><path d="M21 19a2 2 0 0 1-2 2"/><path d="M5 21a2 2 0 0 1-2-2"/><path d="M9 3h1"/><path d="M9 21h1"/><path d="M3 9v1"/><path d="M21 9v1"/>',
    "terminal": '<polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/>',
    "user-round": '<circle cx="12" cy="8" r="5"/><path d="M20 21a8 8 0 0 0-16 0"/>',
    "trash-2": '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v5"/><path d="M14 11v5"/>',
    "x": '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
  };

  function icon(name, size = 20, className = "") {
    const body = icons[name] || icons.file;
    return `<svg class="lucide-icon ${className}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
  }

  window.SKIcons = { icon };
})();
