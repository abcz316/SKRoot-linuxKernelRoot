package org.susfs4skp.guide;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.print.PrintManager;
import android.view.View;
import android.view.WindowInsets;
import android.webkit.JavascriptInterface;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Locale;

/** Offline interactive tutorial. It has no module, root, filesystem or network API. */
public final class GuideActivity extends Activity {
    private static final String HOST = "appassets.androidplatform.net";
    private static final String START = "https://" + HOST + "/guide/index.html";
    private static final String REFERENCE = "https://" + HOST + "/guide/reference/index.html";
    private static final int SAVE_FIGURE = 41;
    private final int[] scales = {90, 100, 115, 130, 150};
    private WebView web;
    private FrameLayout root;
    private ProgressBar loading;
    private SharedPreferences preferences;
    private String pendingFigure;
    private boolean leaving;
    private boolean pendingReferencePrint;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        preferences = getSharedPreferences("reader", MODE_PRIVATE);
        if (state != null) pendingFigure = state.getString("pendingFigure");
        getWindow().setStatusBarColor(Color.WHITE);
        getWindow().setNavigationBarColor(Color.WHITE);
        getWindow().getDecorView().setSystemUiVisibility(
            View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        root = new FrameLayout(this);
        root.setBackgroundColor(Color.rgb(245, 243, 248));
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(
                    WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            } else {
                view.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                    insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            }
            return insets;
        });
        setContentView(root);
        web = new WebView(this);
        web.setBackgroundColor(Color.rgb(245, 243, 248));
        web.setSaveEnabled(false);
        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setBlockNetworkLoads(true);
        settings.setGeolocationEnabled(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setSupportMultipleWindows(false);
        settings.setJavaScriptCanOpenWindowsAutomatically(false);
        settings.setSupportZoom(true);
        settings.setBuiltInZoomControls(true);
        settings.setDisplayZoomControls(false);
        settings.setTextZoom(preferences.getInt("textScale", 100));
        web.addJavascriptInterface(new ReaderBridge(), "GuideApp");
        root.addView(web, new FrameLayout.LayoutParams(-1, -1));
        loading = new ProgressBar(this);
        FrameLayout.LayoutParams spinner = new FrameLayout.LayoutParams(96, 96, android.view.Gravity.CENTER);
        root.addView(loading, spinner);
        web.setWebViewClient(new WebViewClient() {
            @Override public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                return localResource(request.getUrl(), request.getMethod());
            }
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                return !isLocal(request.getUrl());
            }
            @Override public void onPageFinished(WebView view, String url) {
                guidePageFinished(view, url);
            }
            @Override public void onReceivedError(WebView view, android.webkit.WebResourceRequest request,
                                                  android.webkit.WebResourceError error) {
                if (view == web && request.isForMainFrame()) showLoadError();
            }
            @Override public boolean onRenderProcessGone(WebView view, RenderProcessGoneDetail detail) {
                if (view == web) showLoadError();
                return true;
            }
        });
        if (Build.VERSION.SDK_INT >= 33) {
            getOnBackInvokedDispatcher().registerOnBackInvokedCallback(
                android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT, this::handleBack);
        }
        web.loadUrl(START);
    }

    private boolean isLocal(Uri uri) {
        return uri != null && "https".equals(uri.getScheme()) && HOST.equals(uri.getHost())
            && uri.getPort() == -1 && uri.getUserInfo() == null && uri.getPath() != null
            && uri.getPath().startsWith("/guide/");
    }
    private boolean isReference(Uri uri) {
        return isLocal(uri) && "/guide/reference/index.html".equals(uri.getPath());
    }
    private boolean isInteractiveEntry(Uri uri) {
        return isLocal(uri) && "/guide/index.html".equals(uri.getPath());
    }
    private boolean isPrintReference(Uri uri) {
        return isReference(uri) && "print=1".equals(uri.getQuery());
    }
    private void guidePageFinished(WebView view, String url) {
        if (view != web || isFinishing()) return;
        loading.setVisibility(View.GONE);
        if (pendingReferencePrint && url != null && url.equals(view.getUrl())
                && isPrintReference(Uri.parse(url))) {
            pendingReferencePrint = false;
            // Consume the one-shot marker before the system print UI can
            // pause/resume the activity or trigger another finished callback.
            view.evaluateJavascript("history.replaceState(null,'',location.pathname+location.hash)", null);
            prepareReferencePrint(view, 100);
        }
    }
    private WebResourceResponse error(int status, String reason) {
        return new WebResourceResponse("text/plain", "utf-8", status, reason,
            Collections.singletonMap("Cache-Control", "no-store"),
            new ByteArrayInputStream("This reader only serves its bundled manual.".getBytes(StandardCharsets.UTF_8)));
    }
    private WebResourceResponse localResource(Uri uri, String method) {
        if (!isLocal(uri)) return error(403, "Forbidden");
        if (!"GET".equals(method)) return error(405, "Method Not Allowed");
        String asset = uri.getPath().substring(1);
        if (asset.contains("..") || asset.contains("\\") || asset.indexOf('\0') >= 0)
            return error(403, "Forbidden");
        String lower = asset.toLowerCase(Locale.ROOT);
        String mime = lower.endsWith(".html") ? "text/html"
            : lower.endsWith(".js") || lower.endsWith(".mjs") ? "application/javascript"
            : lower.endsWith(".css") ? "text/css"
            : lower.endsWith(".svg") ? "image/svg+xml"
            : lower.endsWith(".png") ? "image/png"
            : lower.endsWith(".jpg") || lower.endsWith(".jpeg") ? "image/jpeg"
            : lower.endsWith(".gif") ? "image/gif"
            : lower.endsWith(".webp") ? "image/webp"
            : lower.endsWith(".avif") ? "image/avif"
            : lower.endsWith(".ico") ? "image/x-icon"
            : lower.endsWith(".woff2") ? "font/woff2"
            : lower.endsWith(".woff") ? "font/woff"
            : lower.endsWith(".ttf") ? "font/ttf"
            : lower.endsWith(".otf") ? "font/otf"
            : lower.endsWith(".json") || lower.endsWith(".map") ? "application/json"
            : lower.endsWith(".xml") ? "application/xml"
            : lower.endsWith(".txt") || lower.endsWith(".md") ? "text/plain" : null;
        if (mime == null) return error(404, "Not Found");
        try {
            InputStream stream = getAssets().open(asset);
            boolean text = mime.startsWith("text/") || "application/javascript".equals(mime)
                || "application/json".equals(mime) || "application/xml".equals(mime)
                || "image/svg+xml".equals(mime);
            return new WebResourceResponse(mime, text ? "utf-8" : null, 200, "OK",
                Collections.singletonMap("Cache-Control", "no-store"), stream);
        } catch (IOException absent) { return error(404, "Not Found"); }
    }
    private void showLoadError() {
        if (isFinishing() || web == null) return;
        pendingReferencePrint = false;
        loading.setVisibility(View.GONE);
        if (web != null) {
            WebView failed = web;
            web = null;
            root.removeView(failed);
            failed.removeJavascriptInterface("GuideApp");
            failed.destroy();
        }
        TextView message = new TextView(this);
        message.setText("手册暂时无法显示。\n请关闭并重新打开应用；也可检查 Android System WebView 是否正常。\n\n点击此处关闭，重新打开即可继续阅读。");
        message.setTextColor(Color.rgb(70, 57, 87));
        message.setBackgroundColor(Color.WHITE);
        message.setPadding(32, 64, 32, 32);
        message.setOnClickListener(view -> finish());
        root.addView(message, new FrameLayout.LayoutParams(-1, -1));
    }
    @Override public void onBackPressed() { handleBack(); }
    private void handleBack() {
        if (leaving || isFinishing()) return;
        if (web == null) { finish(); return; }
        final WebView current = web;
        current.evaluateJavascript("(function(){if(window.GuideAndroid&&GuideAndroid.back)return GuideAndroid.back();return false;})()", handled -> {
            if (isFinishing() || leaving || current != web) return;
            if ("true".equals(handled)) return;
            String url = current.getUrl();
            if (url != null && isReference(Uri.parse(url))) { returnToCover(); return; }
            // WebView keeps joint iframe history. At the shell home screen a
            // false JS result means exit, rather than rewinding a hidden frame.
            if (url != null && isInteractiveEntry(Uri.parse(url))) { leaving = true; finish(); return; }
            if (current.canGoBack()) current.goBack();
            else { leaving = true; finish(); }
        });
    }
    @Override protected void onPause() {
        if (web != null) web.evaluateJavascript("window.GuideAndroid&&GuideAndroid.persist()", null);
        super.onPause();
    }
    @Override protected void onSaveInstanceState(Bundle state) {
        if (pendingFigure != null) state.putString("pendingFigure", pendingFigure);
        super.onSaveInstanceState(state);
    }
    @Override protected void onDestroy() {
        pendingReferencePrint = false;
        if (web != null) {
            root.removeView(web);
            web.removeJavascriptInterface("GuideApp");
            web.destroy();
            web = null;
        }
        super.onDestroy();
    }
    private void readingSettings() {
        if (isFinishing() || web == null) return;
        String[] labels = {"较小 · 90%", "标准 · 100%", "较大 · 115%", "大字 · 130%", "特大 · 150%"};
        int current = preferences.getInt("textScale", 100), selected = 1;
        for (int i = 0; i < scales.length; i++) if (scales[i] == current) selected = i;
        new AlertDialog.Builder(this).setTitle("阅读字号")
            .setSingleChoiceItems(labels, selected, (dialog, which) -> {
                preferences.edit().putInt("textScale", scales[which]).apply();
                if (web != null) web.getSettings().setTextZoom(scales[which]);
            })
            .setPositiveButton("完成", null)
            .setNeutralButton("打印 / PDF", (dialog, which) -> requestPrint())
            .setNegativeButton("返回封面", (dialog, which) -> returnToCover())
            .show();
    }
    private void returnToCover() {
        if (isFinishing() || web == null) return;
        pendingReferencePrint = false;
        String url = web.getUrl();
        if (url != null && isReference(Uri.parse(url))) {
            web.evaluateJavascript("window.GuideAndroid&&GuideAndroid.persist()", null);
            web.loadUrl(START);
        } else web.evaluateJavascript("window.GuideAndroid&&GuideAndroid.cover()", null);
    }
    private void requestPrint() {
        if (isFinishing() || web == null) return;
        String url = web.getUrl();
        if (url != null && isReference(Uri.parse(url))) {
            prepareReferencePrint(web, 100);
        } else if (!pendingReferencePrint) {
            pendingReferencePrint = true;
            web.evaluateJavascript("window.GuideAndroid&&GuideAndroid.persist()", null);
            loading.setVisibility(View.VISIBLE);
            web.loadUrl(REFERENCE + "?print=1");
        }
    }
    private void prepareReferencePrint(WebView target, int attempts) {
        if (isFinishing() || web != target || target.getUrl() == null
                || !isReference(Uri.parse(target.getUrl()))) return;
        target.evaluateJavascript("Boolean(window.GuideAndroidReady&&window.GuideAndroid&&GuideAndroid.print)", ready -> {
            if (isFinishing() || web != target || target.getUrl() == null
                    || !isReference(Uri.parse(target.getUrl()))) return;
            if ("true".equals(ready)) {
                target.evaluateJavascript("window.GuideAndroid.print()", null);
            } else if (attempts > 0) {
                target.postDelayed(() -> prepareReferencePrint(target, attempts - 1), 100);
            } else Toast.makeText(this, "手册仍在加载，请稍后重试打印", Toast.LENGTH_SHORT).show();
        });
    }
    private void printGuide() {
        if (isFinishing() || web == null) return;
        String url = web.getUrl();
        if (url == null || !isReference(Uri.parse(url))) { requestPrint(); return; }
        PrintManager manager = (PrintManager) getSystemService(PRINT_SERVICE);
        if (manager == null) {
            Toast.makeText(this, "系统打印服务不可用", Toast.LENGTH_SHORT).show(); return;
        }
        manager.print("SUSFS 使用手册", web.createPrintDocumentAdapter("SUSFS 使用手册"), null);
    }
    private String figureAsset(String id) throws IOException {
        if (id == null || id.length() > 96 || !id.matches("[a-z0-9]+(?:-[a-z0-9]+)*"))
            throw new IOException("Invalid figure name");
        String reference = "guide/reference/svg/" + id + ".svg";
        try (InputStream ignored = getAssets().open(reference)) { return reference; }
        catch (IOException absent) {
            String legacy = "guide/svg/" + id + ".svg";
            try (InputStream ignored = getAssets().open(legacy)) { return legacy; }
        }
    }
    private void exportSvg(String id) {
        if (id == null || id.length() > 96 || !id.matches("[a-z0-9]+(?:-[a-z0-9]+)*")) return;
        if (pendingFigure != null) return;
        try (InputStream ignored = getAssets().open(figureAsset(id))) {
            pendingFigure = id;
            Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("image/svg+xml");
            intent.putExtra(Intent.EXTRA_TITLE, "SUSFS-" + id + ".svg");
            startActivityForResult(intent, SAVE_FIGURE);
        } catch (Exception failure) {
            pendingFigure = null;
            Toast.makeText(this, "无法打开系统保存窗口", Toast.LENGTH_SHORT).show();
        }
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != SAVE_FIGURE) return;
        final String id = pendingFigure; pendingFigure = null;
        if (result != RESULT_OK || data == null || data.getData() == null || id == null) return;
        final Uri destination = data.getData();
        new Thread(() -> {
            String message;
            try (InputStream source = getAssets().open(figureAsset(id));
                 OutputStream output = getContentResolver().openOutputStream(destination, "w")) {
                if (output == null) throw new IOException("No output stream");
                byte[] buffer = new byte[32768]; int bytes;
                while ((bytes = source.read(buffer)) != -1) output.write(buffer, 0, bytes);
                message = "教学图已保存";
            } catch (Exception failure) { message = "教学图保存失败，请重试"; }
            final String notice = message;
            runOnUiThread(() -> Toast.makeText(this, notice, Toast.LENGTH_SHORT).show());
        }, "guide-export").start();
    }
    private final class ReaderBridge {
        @JavascriptInterface public void showReadingSettings() { runOnUiThread(() -> readingSettings()); }
        @JavascriptInterface public void exportSvg(String id) { runOnUiThread(() -> GuideActivity.this.exportSvg(id)); }
        @JavascriptInterface public void printGuide() { runOnUiThread(() -> GuideActivity.this.printGuide()); }
    }
}
