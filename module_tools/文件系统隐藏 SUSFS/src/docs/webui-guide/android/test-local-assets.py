#!/usr/bin/env python3
"""Run the reader's actual Java resource methods against its packaged APK assets.

This host check extracts production method bodies instead of reimplementing the
allowlist in Python. Android classes are small doubles: Uri uses java.net.URI for
well-formed test URLs; AssetManager opens exact ZIP names without slash repair.
It checks resource responses, not Android WebView rendering or device behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile


def java_method(source: str, name: str) -> str:
    match = re.search(r"(?m)^    private (?:static )?[^\n{};]+\b" + re.escape(name)
                      + r"\([^)]*\)\s*\{", source)
    if match is None:
        raise ValueError(f"Production Java method not found: {name}")
    start = match.start()
    depth, position, state = 1, match.end(), "code"
    while position < len(source):
        char, following = source[position], source[position:position + 2]
        if state in ("string", "char"):
            if char == "\\":
                position += 2
                continue
            if char == ('"' if state == "string" else "'"):
                state = "code"
        elif state == "line":
            if char == "\n":
                state = "code"
        elif state == "block":
            if following == "*/":
                state = "code"
                position += 2
                continue
        elif following in ("//", "/*"):
            state = "line" if following == "//" else "block"
            position += 2
            continue
        elif char in ('"', "'"):
            state = "string" if char == '"' else "char"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if not depth:
                return source[start:position + 1]
        position += 1
    raise ValueError(f"Unterminated Java method: {name}")


URI = r'''package android.net;
import java.net.URI;
public final class Uri {
    private final URI parsed;
    private Uri(String value) { parsed = URI.create(value); }
    public static Uri parse(String value) { return new Uri(value); }
    public String getScheme() { return parsed.getScheme(); }
    public String getHost() { return parsed.getHost(); }
    public int getPort() { return parsed.getPort(); }
    public String getUserInfo() { return parsed.getUserInfo(); }
    public String getPath() { return parsed.getPath(); }
    public String getQuery() { return parsed.getQuery(); }
    public String getEncodedPath() { return parsed.getRawPath(); }
    public String getEncodedAuthority() { return parsed.getRawAuthority(); }
    public String getAuthority() { return parsed.getAuthority(); }
    public String toString() { return parsed.toString(); }
}
'''

RESPONSE = r'''package android.webkit;
import java.io.InputStream;
import java.util.Map;
public final class WebResourceResponse {
    public final String mime, encoding, reason;
    public final int status;
    public final InputStream data;
    public WebResourceResponse(String mime, String encoding, int status, String reason,
            Map<String, String> headers, InputStream data) {
        if (status < 100 || status > 599 || status >= 300 && status < 400)
            throw new IllegalArgumentException("Invalid WebResourceResponse status");
        this.mime=mime; this.encoding=encoding; this.status=status;
        this.reason=reason; this.data=data;
    }
}
'''

ASSETS = r'''package android.content.res;
import java.io.*;
import java.util.*;
import java.util.zip.*;
public final class AssetManager implements AutoCloseable {
    private final ZipFile zip;
    public final Map<String, byte[]> fixtures = new HashMap<>();
    public boolean simulateIoFailure;
    public AssetManager(String apk) throws IOException { zip = new ZipFile(apk); }
    public InputStream open(String path) throws IOException {
        if (simulateIoFailure) throw new IOException("Synthetic APK read failure");
        if (fixtures.containsKey(path)) return new ByteArrayInputStream(fixtures.get(path));
        ZipEntry entry = zip.getEntry("assets/" + path);
        if (entry == null || entry.isDirectory()) throw new FileNotFoundException(path);
        return zip.getInputStream(entry);
    }
    public void close() throws IOException { zip.close(); }
}
'''

HARNESS = r'''
    private static final String PRINT_SERVICE = "print";
    private WebView web;
    private final Loading loading = new Loading();
    private boolean pendingReferencePrint, leaving, finished;
    private final PrintManager printManager = new PrintManager();
    private boolean isFinishing() { return finished; }
    private void finish() { finished = true; }
    private Object getSystemService(String ignored) { return printManager; }
    private static final class View { static final int VISIBLE=0, GONE=8; }
    private static final class Loading {
        int visibility;
        void setVisibility(int value) { visibility=value; }
    }
    private static final class PrintManager {
        int calls;
        void print(String title, Object adapter, Object ignored) { calls++; }
    }
    private static final class Toast {
        static final int LENGTH_SHORT=0;
        static Toast makeText(Object context, String text, int length) { return new Toast(); }
        void show() {}
    }
    private static final class WebView {
        String url;
        boolean ready=true, backHandled=false, canBack=true;
        int backCalls;
        final List<String> loads=new ArrayList<>(), scripts=new ArrayList<>();
        final List<Runnable> delayed=new ArrayList<>();
        WebView(String url) { this.url=url; }
        String getUrl() { return url; }
        void loadUrl(String value) { url=value; loads.add(value); }
        void evaluateJavascript(String script, java.util.function.Consumer<String> callback) {
            scripts.add(script);
            if (callback != null) callback.accept(script.startsWith("Boolean(") ? String.valueOf(ready)
                : script.contains("GuideAndroid.back") ? String.valueOf(backHandled) : "null");
        }
        void postDelayed(Runnable callback, int milliseconds) { delayed.add(callback); }
        boolean canGoBack() { return canBack; }
        void goBack() { backCalls++; }
        Object createPrintDocumentAdapter(String title) { return title; }
        int preparedPrints() { return Collections.frequency(scripts, "window.GuideAndroid.print()"); }
    }
    private void nativeCheck(String label, boolean passed) {
        System.out.println("{\"label\":"+escaped(label)+",\"passed\":"+passed+"}");
    }
    private void checkNativeInteractions() {
        finished=false; leaving=false; web=new WebView(START);
        printGuide();
        nativeCheck("iframe bridge routes to top-level reference", printManager.calls==0
            && web.loads.equals(Collections.singletonList(REFERENCE+"?print=1")) && pendingReferencePrint);
        WebView printing=web;
        guidePageFinished(printing, REFERENCE+"?print=1");
        nativeCheck("reference marker consumed before prepared print", !pendingReferencePrint
            && printing.preparedPrints()==1
            && printing.scripts.contains("history.replaceState(null,'',location.pathname+location.hash)"));
        guidePageFinished(printing, REFERENCE+"?print=1");
        nativeCheck("finished callback cannot repeat automatic print", printing.preparedPrints()==1);
        printGuide();
        nativeCheck("adapter created only on reference top level", printManager.calls==1);
        returnToCover();
        nativeCheck("reference cover returns interactive home", START.equals(printing.url)
            && printing.loads.get(printing.loads.size()-1).equals(START));
        web=new WebView(START); pendingReferencePrint=true;
        guidePageFinished(web, REFERENCE+"?print=1");
        nativeCheck("stale URL callback cannot launch print", web.preparedPrints()==0 && pendingReferencePrint);
        WebView obsolete=new WebView(REFERENCE+"?print=1");
        guidePageFinished(obsolete, obsolete.url);
        nativeCheck("old renderer callback cannot launch print", obsolete.preparedPrints()==0);
        pendingReferencePrint=false; web=new WebView(REFERENCE); web.ready=false;
        requestPrint(); WebView waiting=web;
        nativeCheck("print waits for reference image preparation API", waiting.preparedPrints()==0
            && waiting.delayed.size()==1);
        web=new WebView(START); waiting.delayed.get(0).run();
        nativeCheck("navigating away cancels readiness retry", waiting.preparedPrints()==0);
        finished=false; leaving=false; web=new WebView(START); web.canBack=true;
        handleBack();
        nativeCheck("shell home exits despite iframe joint history", finished && web.backCalls==0);
        finished=false; leaving=false; web=new WebView(START); web.backHandled=true;
        handleBack();
        nativeCheck("overlay-consumed back does not exit", !finished && web.backCalls==0);
        finished=false; leaving=false; web=new WebView(REFERENCE);
        handleBack();
        nativeCheck("reference back returns learning home", !finished && START.equals(web.url));
        finished=false; leaving=false; web=null;
        requestPrint(); printGuide(); returnToCover();
        nativeCheck("destroyed renderer print controls are harmless", printManager.calls==1);
        String[] routes={REFERENCE,REFERENCE+"?print=1",REFERENCE+"?print=1#path-hide",
            REFERENCE+"?print=1&other=1",START+"?print=1",
            "https://example.com/guide/reference/index.html?print=1",REFERENCE+"/extra?print=1"};
        boolean[] expected={false,true,true,false,false,false,false};
        for(int index=0;index<routes.length;index++) nativeCheck("exact print route "+index,
            isPrintReference(Uri.parse(routes[index]))==expected[index]);
    }
    private static String escaped(String value) {
        if (value == null) return "null";
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r") + "\"";
    }
    private void check(String label, String url, String method, int expectedStatus,
            String expectedMime, String requiredText, String expectedSha) {
        try {
            WebResourceResponse response = localResource(url == null ? null : Uri.parse(url), method);
            byte[] body = response.data.readAllBytes(); response.data.close();
            String sha = hex(java.security.MessageDigest.getInstance("SHA-256").digest(body));
            String text = new String(body, StandardCharsets.UTF_8);
            boolean textMime = expectedMime != null && (expectedMime.startsWith("text/")
                || expectedMime.equals("application/javascript") || expectedMime.equals("application/json")
                || expectedMime.equals("application/xml") || expectedMime.equals("image/svg+xml"));
            boolean passed = response.status == expectedStatus
                && (expectedMime == null || expectedMime.equals(response.mime))
                && (expectedMime == null || (textMime ? "utf-8".equals(response.encoding) : response.encoding == null))
                && (requiredText == null || text.contains(requiredText))
                && (expectedSha == null || expectedSha.equals(sha));
            System.out.println("{\"label\":"+escaped(label)+",\"passed\":"+passed
                +",\"url\":"+escaped(url)+",\"status\":"+response.status
                +",\"expected_status\":"+expectedStatus+",\"mime\":"+escaped(response.mime)
                +",\"encoding\":"+escaped(response.encoding)
                +",\"bytes\":"+body.length+",\"sha256\":"+escaped(sha)+"}");
        } catch (Exception failure) {
            System.out.println("{\"label\":"+escaped(label)+",\"passed\":false,\"error\":"
                +escaped(failure.toString())+"}");
        }
    }
    private static String hex(byte[] bytes) {
        StringBuilder output = new StringBuilder();
        for (byte part : bytes) output.append(String.format("%02x", part & 255));
        return output.toString();
    }
    public static void main(String[] args) throws Exception {
        try (AssetManager assets = new AssetManager(args[0])) {
            GuideActivity activity = new GuideActivity(assets);
            // CASES
            activity.checkNativeInteractions();
        }
    }
'''


def run(command: list[str | Path]) -> str:
    result = subprocess.run([str(value) for value in command], capture_output=True,
                            text=True, encoding="utf-8", errors="replace", check=False)
    if result.returncode:
        raise RuntimeError(f"{Path(command[0]).name} failed\n{result.stdout}{result.stderr}")
    return result.stdout


def execute(args: argparse.Namespace) -> dict:
    source_path = (args.source_root / "src/org/susfs4skp/guide/GuideActivity.java").resolve(strict=True)
    source = source_path.read_text(encoding="utf-8-sig")
    constants = []
    for name in ("HOST", "START", "REFERENCE"):
        match = re.search(r"(?m)^    private static final String " + name + r" = [^;]+;", source)
        if not match:
            raise ValueError(f"Missing production constant: {name}")
        constants.append(match.group(0))
    extracted = "\n".join(java_method(source, name) for name in (
        "isLocal", "isReference", "isInteractiveEntry", "isPrintReference", "guidePageFinished",
        "error", "localResource", "handleBack", "returnToCover", "requestPrint",
        "prepareReferencePrint", "printGuide"))
    cases = []

    def case(label: str, url: str | None, status: int, mime: str | None = None,
             method: str = "GET", contains: str | None = None, sha: str | None = None) -> None:
        values = (label, url, method, status, mime, contains, sha)
        cases.append("activity.check(" + ",".join(json.dumps(value, ensure_ascii=True)
                                                   for value in values) + ");")

    origin = "https://appassets.androidplatform.net"
    mime_types = {
        ".html": "text/html", ".js": "application/javascript", ".mjs": "application/javascript",
        ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png",
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
        ".webp": "image/webp", ".avif": "image/avif", ".ico": "image/x-icon",
        ".woff": "font/woff", ".woff2": "font/woff2", ".ttf": "font/ttf", ".otf": "font/otf",
        ".json": "application/json", ".map": "application/json", ".xml": "application/xml",
        ".txt": "text/plain", ".md": "text/plain",
    }
    with zipfile.ZipFile(args.apk) as archive:
        entries = archive.infolist()
        # On Windows ZipInfo.filename silently changes raw backslashes to '/'.
        # Java ZipFile/Android AssetManager do not, so preserve orig_filename in
        # the report and let the real Java ZIP reader expose missing assets.
        assets = [entry.filename for entry in entries
                  if entry.filename.startswith("assets/") and not entry.is_dir()]
        raw_assets = [entry.orig_filename for entry in entries
                      if entry.filename.startswith("assets/") and not entry.is_dir()]
        if "assets/guide/index.html" not in assets:
            raise AssertionError("The actual APK has no guide/index.html asset, even after ZIP normalization")
        index_sha = hashlib.sha256(archive.read("assets/guide/index.html")).hexdigest()
        # Read exact packaged bytes, not the prepared directory on the host.
        cases.append('activity.check("production START", START, "GET", 200, "text/html", "SUSFS", '
                     + json.dumps(index_sha) + ');')
        case("explicit HTTPS port follows canonical-origin allowlist",
             origin + ":443/guide/index.html", 403)
        case("noncanonical host case follows origin allowlist",
             "https://APPASSETS.ANDROIDPLATFORM.NET/guide/index.html", 403)
        case("noncanonical scheme case follows origin allowlist",
             "HTTPS://appassets.androidplatform.net/guide/index.html", 403)
        case("chapter fragment", origin + "/guide/index.html#path-hide", 200,
             "text/html", sha=index_sha)
        case("query and fragment", origin + "/guide/index.html?source=reader#map", 200,
             "text/html", sha=index_sha)
        for name in assets:
            extension = Path(name).suffix.lower()
            mime = mime_types.get(extension)
            if mime:
                case("packaged " + name, origin + "/" + name.removeprefix("assets/"), 200,
                     mime, sha=hashlib.sha256(archive.read(name)).hexdigest())
    # Cover every allowed MIME even if the current WebUI bundles no font/icon.
    # These are explicit AssetManager-double fixtures, never installed assets.
    for extension, mime in mime_types.items():
        fixture_path = "guide/simulator/test-mime-fixture" + extension
        fixture_text = "synthetic-resource-type:" + extension
        cases.append("assets.fixtures.put(" + json.dumps(fixture_path) + ", "
                     + json.dumps(fixture_text) + ".getBytes(StandardCharsets.UTF_8));")
        case("synthetic MIME fixture " + extension, origin + "/" + fixture_path, 200,
             mime, sha=hashlib.sha256(fixture_text.encode()).hexdigest())
    for label, url in (
        ("foreign host", "https://example.com/guide/index.html"),
        ("suffix host", "https://appassets.androidplatform.net.example.com/guide/index.html"),
        ("HTTP origin", "http://appassets.androidplatform.net/guide/index.html"),
        ("foreign HTTPS port", origin + ":8443/guide/index.html"),
        ("userinfo", "https://reader@appassets.androidplatform.net/guide/index.html"),
        ("password userinfo", "https://reader:secret@appassets.androidplatform.net/guide/index.html"),
        ("empty userinfo", "https://@appassets.androidplatform.net/guide/index.html"),
        ("file URL", "file:///android_asset/guide/index.html"),
        ("content URL", "content://org.susfs4skp.guide/guide/index.html"),
        ("wrong root", origin + "/index.html"),
        ("root prefix confusion", origin + "/guide-other/index.html"),
        ("parent traversal", origin + "/guide/../index.html"),
        ("encoded traversal", origin + "/guide/%2e%2e/index.html"),
        ("encoded slash traversal", origin + "/guide/svg/%2e%2e%2findex.html"),
        ("encoded backslash", origin + "/guide/svg%5cindex.html"),
        ("encoded NUL", origin + "/guide/index.html%00.png"),
        ("nested simulator traversal", origin + "/guide/simulator/%2e%2e/index.html"),
        ("reference traversal", origin + "/guide/reference/svg/%2e%2e/index.html"),
    ):
        case(label, url, 403)
    case("null URL", None, 403)
    case("POST rejected", origin + "/guide/index.html", 405, method="POST")
    case("missing asset", origin + "/guide/not-present.json", 404)
    case("unsupported extension", origin + "/guide/fixture.exe", 404)
    cases.append("assets.simulateIoFailure = true;")
    case("AssetManager IO failure", origin + "/guide/index.html", 404)
    cases.append("assets.simulateIoFailure = false;")
    case("read recovers after IO failure", origin + "/guide/index.html", 200,
         "text/html", sha=index_sha)

    generated = args.output / "java"
    activity = ("package org.susfs4skp.guide;\n"
                "import android.net.Uri;\nimport android.webkit.WebResourceResponse;\n"
                "import android.content.res.AssetManager;\nimport java.io.*;\n"
                "import java.nio.charset.StandardCharsets;\nimport java.util.*;\n"
                "public final class GuideActivity {\n" + "\n".join(constants)
                + "\nprivate final AssetManager assets;\n"
                "private GuideActivity(AssetManager assets) { this.assets = assets; }\n"
                "private AssetManager getAssets() { return assets; }\n" + extracted
                + HARNESS.replace("// CASES", "\n".join(cases)) + "\n}\n")
    sources = {"android/net/Uri.java": URI, "android/webkit/WebResourceResponse.java": RESPONSE,
               "android/content/res/AssetManager.java": ASSETS,
               "org/susfs4skp/guide/GuideActivity.java": activity}
    for relative, content in sources.items():
        target = generated / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    classes = args.output / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    suffix = ".exe" if sys.platform == "win32" else ""
    run([args.jdk_root / f"bin/javac{suffix}", "-encoding", "UTF-8", "-d", classes,
         *(generated / relative for relative in sources)])
    output = run([args.jdk_root / f"bin/java{suffix}", "-cp", classes,
                  "org.susfs4skp.guide.GuideActivity", args.apk.resolve(strict=True)])
    results = [json.loads(line) for line in output.splitlines() if line.strip()]
    return {"passed": bool(results) and all(item["passed"] for item in results),
            "source": str(source_path), "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
            "extracted_methods_sha256": hashlib.sha256(extracted.encode()).hexdigest(),
            "apk": str(args.apk.resolve()), "apk_sha256": hashlib.sha256(args.apk.read_bytes()).hexdigest(),
            "apk_asset_count": len(assets), "raw_asset_backslash_count": sum("\\" in name for name in raw_assets),
            "raw_start_asset_present": "assets/guide/index.html" in raw_assets,
            "case_count": len(results),
            "mime_fixture_count": len(mime_types),
            "failures": [item for item in results if not item["passed"]], "results": results,
            "limits": "Host Java method regression with URI/AssetManager doubles; no Android WebView/device test."}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--jdk-root", type=Path, default=Path("C:/Program Files/Java/jdk-17"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        args.output.mkdir(parents=True, exist_ok=True)
        report = execute(args)
        (args.output / "local-assets-report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        summary = {key: value for key, value in report.items() if key not in ("results", "failures")}
        summary["failure_count"] = len(report["failures"])
        summary["first_failures"] = report["failures"][:3]
        print(json.dumps(summary,
                         ensure_ascii=False, indent=2))
        return 0 if report["passed"] else 1
    except (AssertionError, OSError, ValueError, RuntimeError, zipfile.BadZipFile) as error:
        print(f"Local asset routing verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
