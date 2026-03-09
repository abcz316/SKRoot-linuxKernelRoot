package com.linux.permissionmanager.update;

import android.app.Activity;
import android.net.Uri;
import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.linux.permissionmanager.utils.DownloadDialogHelper;
import com.linux.permissionmanager.utils.FileUtils;

import java.io.File;

public class SkrModDownloader {

    public interface Callback {
        void onSuccess(@NonNull File file);
        void onError(@NonNull Exception e);
    }

    /** 自动删除策略 */
    public enum AutoDelete {
        NONE,       // 不自动删
        ON_ERROR,   // 失败自动删
        ON_SUCCESS, // 成功回调后自动删
        ON_BOTH     // 成功/失败都自动删
    }

    private final Activity mActivity;

    public SkrModDownloader(@NonNull Activity activity) {
        this.mActivity = activity;
    }

    // ---------------- public API ----------------

    /** 默认：不自动删 */
    public void downloadToCache(@NonNull String url, @Nullable String fileNameHint, @Nullable Callback cb) {
        downloadToCache(url, fileNameHint, AutoDelete.NONE, cb);
    }

    /** 支持自动删除策略 */
    public void downloadToCache(@NonNull String url, @Nullable String fileNameHint, @NonNull AutoDelete autoDelete, @Nullable Callback cb) {
        if (TextUtils.isEmpty(url)) {
            postError(cb, new IllegalArgumentException("url is empty"));
            return;
        }

        File dir = getDefaultCacheDir();
        if (!ensureDir(dir)) {
            postError(cb, new IllegalStateException("create cache dir failed: " + dir.getAbsolutePath()));
            return;
        }

        String fileName = buildFileName(url, fileNameHint);
        File destFile = new File(dir, fileName);
        downloadToFile(url, destFile, autoDelete, cb);
    }

    /** 下载到指定文件（默认不自动删） */
    public void downloadToFile(@NonNull String url, @NonNull File destFile, @Nullable Callback cb) {
        downloadToFile(url, destFile, AutoDelete.NONE, cb);
    }

    /** 下载到指定文件（支持自动删） */
    public void downloadToFile(@NonNull String url, @NonNull File destFile, @NonNull AutoDelete autoDelete, @Nullable Callback cb) {
        if (TextUtils.isEmpty(url)) {
            postError(cb, new IllegalArgumentException("url is empty"));
            return;
        }
        File parent = destFile.getParentFile();
        if (parent != null && !ensureDir(parent)) {
            postError(cb, new IllegalStateException("create dest dir failed: " + parent.getAbsolutePath()));
            return;
        }

        DownloadDialogHelper.startDownloadWithDialog(mActivity, url, destFile,
                new DownloadDialogHelper.DownloadResultCallback() {
                    @Override
                    public void onSuccess(File file) {
                        final File out = (file != null) ? file : destFile;
                        mActivity.runOnUiThread(() -> {
                            try {
                                if (cb != null) cb.onSuccess(out);
                            } finally {
                                if (autoDelete == AutoDelete.ON_SUCCESS || autoDelete == AutoDelete.ON_BOTH) {
                                    safeDelete(out);
                                }
                            }
                        });
                    }

                    @Override
                    public void onError(Exception e) {
                        final Exception ex = (e != null) ? e : new RuntimeException("download failed: unknown error");
                        mActivity.runOnUiThread(() -> {
                            try {
                                if (cb != null) cb.onError(ex);
                            } finally {
                                if (autoDelete == AutoDelete.ON_ERROR || autoDelete == AutoDelete.ON_BOTH) {
                                    safeDelete(destFile);
                                }
                            }
                        });
                    }
                }
        );
    }

    // ---------------- internal ----------------

    private File getDefaultCacheDir() {
        return new File(mActivity.getCacheDir(), "skrmods");
    }

    private boolean ensureDir(@NonNull File dir) {
        if (dir.exists()) return dir.isDirectory();
        return dir.mkdirs();
    }

    private String buildFileName(@NonNull String url, @Nullable String fileNameHint) {
        if (!TextUtils.isEmpty(fileNameHint)) return sanitizeFileName(fileNameHint);

        try {
            Uri uri = Uri.parse(url);
            String last = uri.getLastPathSegment();
            if (!TextUtils.isEmpty(last)) return sanitizeFileName(last);
        } catch (Exception ignored) {}

        return "skrmod_" + System.currentTimeMillis() + ".zip";
    }

    private String sanitizeFileName(@NonNull String name) {
        String n = name.trim();
        if (n.isEmpty()) return "skrmod_" + System.currentTimeMillis() + ".zip";
        n = n.replaceAll("[\\\\/:*?\"<>|]", "_");
        return n;
    }

    private void safeDelete(@NonNull File f) {
        try {
            FileUtils.deleteFile(f);
        } catch (Throwable t) {
            try {
                f.delete();
            } catch (Throwable ignored) {}
        }
    }

    private void postError(@Nullable Callback cb, @NonNull Exception e) {
        if (cb == null) return;
        mActivity.runOnUiThread(() -> cb.onError(e));
    }
}
