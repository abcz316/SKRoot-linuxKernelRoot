// SPDX-License-Identifier: GPL-2.0-only
#pragma once

namespace susfs::management {
// User-provided defaults (2026-10-22), with no-background enabled. Used only
// when the module's config.json is absent; ordinary edits are never reseeded.
inline constexpr char kInitialInstallConfig[] = R"json({
  "schema": 14,
  "mode": "groups",
  "object_rules_enabled": true,
  "subjects": {
    "mode": "whitelist", "exempt_root": true, "exempt_system_processes": true,
    "exempt_system_apps": true, "whitelist_packages": [], "blacklist_packages": []
  },
  "profiles": [
    {
      "id": 0, "name": "默认", "packages": [],
      "rules": { "paths": [{"path": "/mnt/vendor/persist/data", "hide_contents": true}, {"path": "/mnt/vendor/nvdata", "hide_contents": true}], "kstats": [], "maps": [], "redirects": [], "mounts": [] },
      "subjects": {
        "mode": "whitelist", "exempt_root": true, "exempt_system_processes": true,
        "exempt_system_apps": false, "whitelist_packages": [],
        "blacklist_packages": ["bin.mt.plus", "com.android.documentsui", "com.coloros.filemanager"]
      }
    },
    {
      "id": 1, "name": "仅root", "packages": [],
      "rules": { "paths": [{"path": "/data/adb", "hide_contents": true}], "kstats": [], "maps": [], "redirects": [], "mounts": [] },
      "subjects": {
        "mode": "whitelist", "exempt_root": true, "exempt_system_processes": false,
        "exempt_system_apps": false, "whitelist_packages": [], "blacklist_packages": []
      }
    }
  ],
  "path_scopes": [],
  "globals": { "avc_spoof": "0", "enable_log": "0" },
  "webui": { "no_background": true }
})json";
}
