package com.linux.permissionmanager.utils.repack;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.AdaptiveIconDrawable;
import android.graphics.drawable.Drawable;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** 将外部 Drawable 渲染成模板对应的普通、前景、背景 PNG。 */
final class ApkIconProcessor {
    private static final int ICON_SIZE = 512;
    private static final Pattern PNG_ENTRY_PATH = Pattern.compile("res/[A-Za-z0-9_./-]+\\.png");
    private ApkIconProcessor() {}

/** 把 Drawable 统一映射到可配置的三个 PNG 资源，适配固定图标模板。 */
static Map<String, byte[]> renderIconReplacements(Drawable icon, ApkGenerator.IconPaths paths) throws IOException {
    if (paths == null) throw new IllegalArgumentException("customIcon 非 null 时必须设置 iconPaths");
    validateIconPath(paths.legacyPng);
    validateIconPath(paths.foregroundPng);
    validateIconPath(paths.backgroundPng);
    Set<String> distinct = new LinkedHashSet<>();
    distinct.add(paths.legacyPng);
    distinct.add(paths.foregroundPng);
    distinct.add(paths.backgroundPng);
    if (distinct.size() != 3) throw new IllegalArgumentException("三个图标 ZIP 路径不能相同");

    Map<String, byte[]> result = new LinkedHashMap<>();
    // 传统图标：整个 Drawable 的当前显示效果，包括 Adaptive Icon 的系统蒙版。
    result.put(paths.legacyPng, renderPng(icon, 0));
    if (android.os.Build.VERSION.SDK_INT >= 26 && icon instanceof AdaptiveIconDrawable) {
        AdaptiveIconDrawable adaptive = (AdaptiveIconDrawable) icon;
        Drawable fg = adaptive.getForeground();
        Drawable bg = adaptive.getBackground();
        if (fg == null || bg == null) throw new IOException("AdaptiveIconDrawable 缺少前景或背景图层");
        // 原生两层分开渲染，不将已经裁剪的图标误当作前景层。
        result.put(paths.foregroundPng, renderPng(fg, 0));
        result.put(paths.backgroundPng, renderPng(bg, 0));
    } else {
        // 普通图标：缩放到自适应图标中心约 2/3 的安全区，背景透明。
        result.put(paths.foregroundPng, renderPng(icon, ICON_SIZE / 6));
        result.put(paths.backgroundPng, transparentPng());
    }
    return result;
}

private static void validateIconPath(String path) {
    if (path == null || !PNG_ENTRY_PATH.matcher(path).matches()
            || path.contains("..") || path.contains("//")) {
        throw new IllegalArgumentException("图标路径必须是 APK 内已有的 res/*.png ZIP 条目: " + path);
    }
}

/** 等比绘制 Drawable；恢复原 bounds，避免改变调用方持有的对象状态。 */
private static byte[] renderPng(Drawable drawable, int padding) throws IOException {
    if (drawable == null) throw new IllegalArgumentException("drawable == null");
    Bitmap bitmap = Bitmap.createBitmap(ICON_SIZE, ICON_SIZE, Bitmap.Config.ARGB_8888);
    Rect old = new Rect(drawable.getBounds());
    try {
        Canvas canvas = new Canvas(bitmap);
        int available = ICON_SIZE - padding * 2;
        int sourceW = drawable.getIntrinsicWidth();
        int sourceH = drawable.getIntrinsicHeight();
        if (sourceW <= 0) sourceW = available;
        if (sourceH <= 0) sourceH = available;
        float scale = Math.min((float) available / sourceW, (float) available / sourceH);
        int w = Math.max(1, Math.min(available, Math.round(sourceW * scale)));
        int h = Math.max(1, Math.min(available, Math.round(sourceH * scale)));
        int x = (ICON_SIZE - w) / 2;
        int y = (ICON_SIZE - h) / 2;
        drawable.setBounds(x, y, x + w, y + h);
        drawable.draw(canvas);
        return encodePng(bitmap);
    } finally {
        drawable.setBounds(old);
        bitmap.recycle();
    }
}

private static byte[] transparentPng() throws IOException {
    Bitmap bitmap = Bitmap.createBitmap(ICON_SIZE, ICON_SIZE, Bitmap.Config.ARGB_8888);
    try {
        return encodePng(bitmap);
    } finally {
        bitmap.recycle();
    }
}

private static byte[] encodePng(Bitmap bitmap) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream(128 * 1024);
    if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)) {
        throw new IOException("Drawable 转 PNG 失败");
    }
    return out.toByteArray();
}

}
