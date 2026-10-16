package com.linux.permissionmanager.utils;

import android.content.res.Resources;
import android.util.TypedValue;

import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 通过资源 ID 获取当前 APK 内 PNG 资源的实际 ZIP 条目路径。
 *
 * <p>AAPT2 在编译时会压缩资源路径（例如 dynamic_icon_background 变为 res/bQ.png），
 * 且每次重新编译后路径可能变化，因此不能硬编码，而是通过
 * {@link Resources#getValue(int, TypedValue, boolean)} 在运行时动态解析。</p>
 */
public final class IconResourceUtils {

    private IconResourceUtils() {}

    /**
     * 获取指定图片资源在当前 APK ZIP 中的实际条目路径。
     *
     * @param res   应用的 Resources
     * @param resId 指向 PNG 文件的资源 ID（例如 R.drawable.dynamic_icon_legacy）
     * @return 形如 "res/xx.png" 的 APK 内路径
     * @throws IllegalStateException 资源不是文件，或不是 APK 内的 PNG
     */
    public static String getResourcePath(Resources res, int resId) {
        TypedValue value = new TypedValue();
        res.getValue(resId, value, true);
        if (value.type != TypedValue.TYPE_STRING || value.string == null) throw new IllegalStateException("资源不是文件: " + resId);
        String path = value.string.toString();
        if (!path.startsWith("res/") || !path.endsWith(".png")) throw new IllegalStateException("资源不是 APK 内 PNG: " + path);
        return path;
    }

    /**
     * 校验给定资源路径确实存在于指定 APK 的 ZIP 条目中。
     *
     * @param sourceApkPath 当前 App 自身的 APK 路径（context.getApplicationInfo().sourceDir）
     * @param resourcePath  由 {@link #getResourcePath(Resources, int)} 得到的路径
     * @return 存在且为普通条目时返回 true
     * @throws IOException 打开 APK 失败
     */
    public static boolean isInApk(String sourceApkPath, String resourcePath) throws IOException {
        try (ZipFile zip = new ZipFile(sourceApkPath)) {
            ZipEntry entry = zip.getEntry(resourcePath);
            return entry != null && !entry.isDirectory();
        }
    }
}
