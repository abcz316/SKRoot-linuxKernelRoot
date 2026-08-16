package com.linux.permissionmanager.helper;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Build;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;

import androidx.annotation.RequiresApi;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

public class MagicaRootHelper {
    public interface CompletionCallback {
        void onComplete();
    }
    public interface LineCallback {
        void onLine(String line);
    }
    @RequiresApi(api = Build.VERSION_CODES.Q)
    public static void executeMagicaRootScript(Context context, String script, CompletionCallback callback) {
        executeMagicaRootScript(context, script, callback, null);
    }

    @RequiresApi(api = Build.VERSION_CODES.Q)
    public static void executeMagicaRootScript(Context context, String script, CompletionCallback callback, LineCallback lineCallback) {
        AtomicBoolean finished = new AtomicBoolean(false);
        ServiceConnection connection = new ServiceConnection() {
            private IRemoteService remoteService;

            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                remoteService = IRemoteService.Stub.asInterface(service);
                new Thread(() -> {
                    IRemoteProcess remoteProcess = null;
                    try {
                        remoteProcess = remoteService.getRemoteProcess();
                    } catch (RemoteException e) {
                        e.printStackTrace();
                    }
                    if (remoteProcess == null) {
                        emitLine(lineCallback, "ERROR: remote process is null");
                        postCompleteOnce(context, finished, callback);
                        safeUnbind(context, this);
                        return;
                    }
                    final RemoteProcess process = new RemoteProcess(remoteProcess);
                    ByteArrayOutputStream stdoutBuffer = new ByteArrayOutputStream();
                    ByteArrayOutputStream stderrBuffer = new ByteArrayOutputStream();

                    Thread outThread = new Thread(() -> copyStream(process.getInputStream(), stdoutBuffer, lineCallback), "Magica-stdout");
                    Thread errThread = new Thread(() -> copyStream(process.getErrorStream(), stderrBuffer, lineCallback), "Magica-stderr");
                    try {
                        outThread.start();
                        errThread.start();
                        OutputStream stdin = process.getOutputStream();
                        writeStringChunked(stdin, script, 4096);
                        stdin.flush();
                        stdin.close();

                        process.waitFor();

                        outThread.join();
                        errThread.join();

                        postCompleteOnce(context, finished, callback);
                    } catch (Throwable t) {
                        try {
                            process.destroy();
                        } catch (Throwable ignore) {}
                        try {
                            outThread.join(300);
                            errThread.join(300);
                        } catch (InterruptedException ignored) {
                            Thread.currentThread().interrupt();
                        }

                        emitLine(lineCallback, "ERROR: " + t.getMessage());
                        postCompleteOnce(context, finished, callback);
                    } finally {
                        try {
                            if (process != null) process.destroy();
                        } catch (Throwable ignore) {}
                        safeUnbind(context, this);
                    }
                }, "Magica-Exec").start();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                emitLine(lineCallback, "ERROR: service disconnected");
                postCompleteOnce(context, finished, callback);
            }
        };

        try {
            Intent intent = new Intent(context, MagicaService.class);
            Executor executor = context.getMainExecutor();
            boolean ok = context.bindIsolatedService(intent, Context.BIND_AUTO_CREATE, "magica", executor, connection);
            if (!ok) {
                emitLine(lineCallback, "ERROR: bindIsolatedService returned false");
                postCompleteOnce(context, finished, callback);
            }
        } catch (Throwable t) {
            emitLine(lineCallback, "ERROR: bindIsolatedService failed - " + t.getMessage());
            postCompleteOnce(context, finished, callback);
        }
    }

    private static void writeStringChunked(OutputStream os, String text, int chunkSize) throws IOException {
        if (os == null) throw new IllegalArgumentException("OutputStream == null");
        if (text == null) text = "";
        if (chunkSize <= 0) throw new IllegalArgumentException("chunkSize must > 0");
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        int offset = 0;
        while (offset < data.length) {
            int len = Math.min(chunkSize, data.length - offset);
            os.write(data, offset, len);
            offset += len;
        }
    }
    private static void copyStream(InputStream in, ByteArrayOutputStream out) {
        copyStream(in, out, null);
    }

    private static void copyStream(InputStream in, ByteArrayOutputStream out, LineCallback lineCallback) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                out.write((line + "\n").getBytes(StandardCharsets.UTF_8));
                if (lineCallback != null) lineCallback.onLine(line);
            }
        } catch (IOException ignored) {
        } finally {
            try {
                in.close();
            } catch (IOException ignored) {}
        }
    }

    private static void safeUnbind(Context context, ServiceConnection conn) {
        try {
            context.unbindService(conn);
        } catch (Throwable ignore) {}
    }

    private static void emitLine(LineCallback lineCallback, String line) {
        if (lineCallback != null) lineCallback.onLine(line);
    }

    private static void postCompleteOnce(Context context, AtomicBoolean finished, CompletionCallback callback) {
        if (!finished.compareAndSet(false, true)) return;
        if (Looper.myLooper() == Looper.getMainLooper()) {
            callback.onComplete();
        } else {
            context.getMainExecutor().execute(callback::onComplete);
        }
    }
}