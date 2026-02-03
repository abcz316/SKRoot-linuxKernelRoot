package com.linux.permissionmanager.utils;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import java.io.File;

public final class DownloadDialogHelper {

    private DownloadDialogHelper() {
        throw new AssertionError("No DownloadDialogHelper instances!");
    }

    /**
     * 带系统 ProgressDialog 的下载封装
     *
     * @param activity     当前 Activity（用来跑 runOnUiThread 和创建对话框）
     * @param url          下载链接
     * @param destFile     目标文件
     * @param callback     下载回调（可为 null）
     */
    public static void startDownloadWithDialog(
            Activity activity,
            String url,
            File destFile,
            DownloadResultCallback callback
    ) {
        ProgressDialog dialog = new ProgressDialog(activity);
        dialog.setTitle("正在下载");
        dialog.setMessage("准备中...");
        dialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
        dialog.setIndeterminate(true);
        dialog.setCancelable(true);

        // 标记是否用户主动取消，用来决定是否回调 onSuccess
        final boolean[] isCanceled = {false};

        // 负按钮：取消
        dialog.setButton(DialogInterface.BUTTON_NEGATIVE, "取消",
                (d, which) -> {
                    isCanceled[0] = true;
                    d.dismiss();
                    // 这里只是关闭对话框，底层 NetUtils 暂时还没有取消逻辑
                    // 如果以后 NetUtils 支持取消，这里可以顺便调用 cancel
                });

        // 按返回键关闭对话框时，也视为取消
        dialog.setOnCancelListener(d -> isCanceled[0] = true);
        dialog.show();

        NetUtils.downloadFile(url, destFile, new NetUtils.DownloadCallback() {
            @Override
            public void onStart(long totalBytes) {
                activity.runOnUiThread(() -> {
                    if (totalBytes > 0) {
                        dialog.setIndeterminate(false);
                        dialog.setMax(100);
                    } else {
                        dialog.setIndeterminate(true);
                        dialog.setMessage("大小未知，正在下载...");
                    }
                });
            }

            @Override
            public void onProgress(long downloadedBytes, long totalBytes) {
                activity.runOnUiThread(() -> {
                    if (totalBytes > 0) {
                        int progress = (int) (downloadedBytes * 100 / totalBytes);
                        dialog.setIndeterminate(false);
                        dialog.setProgress(progress);

                        String msg = String.format("%s / %s", FileUtils.formatFileSize(downloadedBytes), FileUtils.formatFileSize(totalBytes));
                        dialog.setMessage(msg);
                    } else {
                        dialog.setIndeterminate(true);
                        String msg = String.format("%s / ?", FileUtils.formatFileSize(downloadedBytes));
                        dialog.setMessage(msg);
                    }
                });
            }

            @Override
            public void onCompleted(File file) {
                activity.runOnUiThread(() -> {
                    dialog.dismiss();
                    if (!isCanceled[0] && callback != null) {
                        // 只有没被用户取消时才通知成功
                        callback.onSuccess(file);
                    }
                });
            }

            @Override
            public void onError(Exception e) {
                activity.runOnUiThread(() -> {
                    dialog.dismiss();
                    if (callback != null) {
                        callback.onError(e);   // 失败回调出去，带原因
                    }
                });
            }
        });
    }

    public interface DownloadResultCallback {
        void onSuccess(File destFile);
        void onError(Exception e);
    }
}
