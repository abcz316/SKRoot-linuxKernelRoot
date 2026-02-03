package com.linux.permissionmanager.utils;

import org.json.JSONException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;

public final class NetUtils {

    // 工具类不允许实例化
    private NetUtils() {
        throw new AssertionError("No NetUtils instances for you!");
    }

    public static final class DownloadHandle {
        private volatile boolean cancelled = false;
        private Thread workerThread;

        private void setWorkerThread(Thread t) {
            this.workerThread = t;
        }

        /** 外面调用这个方法取消下载 */
        public void cancel() {
            cancelled = true;
            // 如果有阻塞 read，可以通过中断加快结束
            if (workerThread != null) {
                workerThread.interrupt();
            }
        }

        public boolean isCancelled() {
            return cancelled;
        }
    }

    //==================================================================
    // 1) 下载文本（.txt / .json 等），内部开新线程，通过回调返回
    //==================================================================

    /**
     * 异步下载文本内容（适合 .txt / .json 等），支持取消
     *
     * @param urlString  形如 "https://example.com/config.json"
     * @param callback   下载结果回调（在子线程调用）
     * @return DownloadHandle  可通过 handle.cancel() 取消
     *
     * 注意：
     *  - callback 的 onSuccess/onError 都在内部新开的子线程中调用，
     *    如果要更新 UI，需要自己在外面切回主线程（比如 runOnUiThread）。
     */
    public static DownloadHandle downloadText(final String urlString,
                                              final TextDownloadCallback callback) {
        final DownloadHandle handle = new DownloadHandle();

        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                URLConnection conn = null;
                InputStream is = null;
                BufferedReader br = null;

                try {
                    URL myURL = new URL(urlString);
                    conn = myURL.openConnection();
                    conn.setConnectTimeout(1000 * 60 * 5);
                    conn.setReadTimeout(1000 * 60 * 5);
                    conn.connect();

                    is = conn.getInputStream();
                    br = new BufferedReader(
                            new InputStreamReader(is, StandardCharsets.UTF_8)
                    );

                    StringBuilder sb = new StringBuilder();
                    String line;

                    while ((line = br.readLine()) != null) {
                        // 每次读一行都检查是否被取消
                        if (handle.isCancelled()) {
                            throw new IOException("Text download cancelled");
                        }
                        sb.append(line).append('\n');
                    }

                    // 读完再检查一次
                    if (handle.isCancelled()) {
                        throw new IOException("Text download cancelled");
                    }

                    if (callback != null) {
                        callback.onSuccess(sb.toString());
                    }
                } catch (Exception e) {
                    if (callback != null) {
                        if (handle.isCancelled()) {
                            callback.onError(new IOException("文本下载已被取消", e));
                        } else {
                            callback.onError(e);
                        }
                    }
                } finally {
                    try {
                        if (br != null) br.close();
                    } catch (IOException ignored) {}
                    try {
                        if (is != null) is.close();
                    } catch (IOException ignored) {}
                }
            }
        });

        handle.setWorkerThread(t);
        t.start();
        return handle;
    }

    public interface TextDownloadCallback {
        void onSuccess(String content) throws JSONException;
        void onError(Exception e);
    }

    //==================================================================
    // 2) 下载文件到本地，带进度回调，内部开新线程
    //==================================================================

    /**
     * 异步下载文件到本地 destFile
     *
     * @param urlString  下载链接
     * @param destFile   目标文件路径（会自动创建父目录）
     * @param callback   下载进度/结果回调（在子线程调用）
     * @return DownloadHandle  通过 handle.cancel() 取消下载
     */
    public static DownloadHandle downloadFile(final String urlString,
                                              final File destFile,
                                              final DownloadCallback callback) {
        final DownloadHandle handle = new DownloadHandle();

        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                URLConnection conn = null;
                InputStream is = null;
                FileOutputStream fos = null;
                File tmpFile = null;

                try {
                    URL myURL = new URL(urlString);
                    conn = myURL.openConnection();
                    conn.setConnectTimeout(1000 * 60 * 5);
                    conn.setReadTimeout(1000 * 60 * 5);
                    conn.connect();

                    int fileSize = conn.getContentLength(); // 可能为 -1

                    if (callback != null && !handle.isCancelled()) {
                        callback.onStart(fileSize);
                    }

                    // 确保目录存在
                    File parent = destFile.getParentFile();
                    if (parent != null && !parent.exists()) {
                        if (!parent.mkdirs() && !parent.isDirectory()) {
                            throw new IOException("无法创建目录: " + parent.getAbsolutePath());
                        }
                    }

                    // 临时文件
                    tmpFile = new File(destFile.getAbsolutePath() + ".download");

                    is = conn.getInputStream();
                    fos = new FileOutputStream(tmpFile);

                    byte[] buffer = new byte[8 * 1024];
                    int len;
                    long totalRead = 0;

                    while ((len = is.read(buffer)) != -1) {
                        // 每次读完先检查是否取消
                        if (handle.isCancelled()) {
                            throw new IOException("Download cancelled");
                        }

                        fos.write(buffer, 0, len);
                        totalRead += len;

                        if (callback != null && !handle.isCancelled()) {
                            callback.onProgress(totalRead, fileSize);
                        }
                    }

                    // 再检查一次是否取消
                    if (handle.isCancelled()) {
                        throw new IOException("Download cancelled");
                    }

                    fos.getFD().sync();

                    if (!tmpFile.renameTo(destFile)) {
                        throw new IOException("重命名下载文件失败: " + tmpFile.getAbsolutePath());
                    }

                    if (callback != null && !handle.isCancelled()) {
                        callback.onCompleted(destFile);
                    }

                } catch (Exception e) {
                    if (callback != null) {
                        // 你可以选择区分“取消”和“真实错误”
                        if (handle.isCancelled()) {
                            // 可选：如果你愿意，可以给 DownloadCallback 增加 onCancelled()
                            callback.onError(new IOException("下载已被取消", e));
                        } else {
                            callback.onError(e);
                        }
                    }
                } finally {
                    try {
                        if (fos != null) fos.close();
                    } catch (IOException ignored) {}
                    try {
                        if (is != null) is.close();
                    } catch (IOException ignored) {}

                    // 失败/取消时清理临时文件
                    if (tmpFile != null && tmpFile.exists() && !tmpFile.equals(destFile)) {
                        //noinspection ResultOfMethodCallIgnored
                        tmpFile.delete();
                    }
                }
            }
        });

        handle.setWorkerThread(t);
        t.start();
        return handle;
    }

    public interface DownloadCallback {
        /** 开始下载时调用，totalBytes 可能为 -1（服务端没返回 Content-Length） */
        void onStart(long totalBytes);

        /** 进度回调：downloadedBytes 已下载字节数，totalBytes 总字节数（可能为 -1） */
        void onProgress(long downloadedBytes, long totalBytes);

        /** 下载完成 */
        void onCompleted(File destFile);

        /** 失败 */
        void onError(Exception e);
    }


}
