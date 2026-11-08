// SPDX-License-Identifier: GPL-2.0-only
#pragma once

// This is the identity of the optional standalone SDK package.  It is kept
// separate from the PLUS module ID and must not be generated per build.
#define SUSFS_STANDALONE_MODULE_ID "fa362333cf458e832cd032fda9a9f3c6"
#define SUSFS_STANDALONE_VERSION "0.3.11"

namespace susfs_standalone {
inline constexpr const char* module_id = SUSFS_STANDALONE_MODULE_ID;
inline constexpr const char* version = SUSFS_STANDALONE_VERSION;
}
