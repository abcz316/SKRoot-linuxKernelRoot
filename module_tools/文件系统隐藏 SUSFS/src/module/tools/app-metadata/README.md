# Application presentation metadata

`PlusAppMetadata.java` is a read-only, one-shot `app_process` helper. It reads one
JSON object from standard input and writes one JSON object to standard output.
It does not install an app, create a listener, read app business data, or accept
credentials. The module starts it through anonymous pipes under the module's
existing root context; its DEX is a read-only resource inside the module.
Before first use, the native service validates the root-owned regular resource
and normalizes the SDK's extraction permissions to `0444`, then confirms its
identity and read-only mode again. Symlinks, hardlinks and foreign owners are rejected.

Build using `./tools/app-metadata/build.ps1 -OutputDirectory <build-directory>`.
The normal PLUS package builder includes the resulting `app-metadata.dex`.
For a device developer check, run the helper with `CLASSPATH` pointing to the
read-only DEX and `/system/bin/app_process /system/bin PlusAppMetadata`, supplying
`{"packages":["org.susfs4skp.forceprobe"],"includeIcons":true}` on stdin and then EOF.

The helper uses PackageManager and framework Resources for localized labels and
96×96 PNG rendering. Framework decoding supports bitmap, vector and adaptive
drawables and installed split resources. When an OEM restricts system-context
access, the fallback reads PackageManager's ApplicationInfo and adds its base,
split, shared-library and overlay resources explicitly. Apps without a declared
icon use the local framework default; the OEM `getDefaultActivityIcon()` Binder
path is deliberately avoided because it can reject `app_process` callers.

The public `POST /api/apps/metadata` endpoint uses the existing PLUS session and
origin checks. It accepts at most 64 package names, or 16 when `includeIcons` is
true. It returns `data.apps` with `package`, `uid`, `label`, `iconPng` (plain PNG
base64), `status` (`ok`, `not_found`, `unavailable`) and `version`, plus `data.locale`.
Failure of one item never fails the entire batch. Helper-only `diagnostic` and
`unchanged` fields are not exposed by the endpoint. Labels and icon metadata are
presentation only; SUSFS retains responsibility for package/UID identity facts.

Each request confirms the package version, update time, installed resource files
and system configuration before reusing a cached rendering. Failed entries are
not stored as successful metadata. The service allows at most two distinct helper
requests at once and coalesces identical in-flight requests. Output is capped at
1.5 MiB and a five-second deadline kills/reaps a stuck helper process group.

Native host coverage lives in `tests/app_metadata_service_test.cpp`; device
verification additionally needs actual bitmap/vector/adaptive/split packages.
