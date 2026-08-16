package com.linux.permissionmanager.utils;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class ShellUtils {

    public interface LineCallback {
        void onLine(String line);
    }

    private static final String SCRIPT_FILE_NAME = "temp_script.sh";

    public static boolean executeScript(Context context, String scriptContent) {
        File defaultFile = new File(context.getCacheDir(), SCRIPT_FILE_NAME);
        return executeScript( scriptContent, defaultFile.getAbsolutePath());
    }

    public static boolean executeScript(Context context, String scriptContent, LineCallback callback) {
        File defaultFile = new File(context.getCacheDir(), SCRIPT_FILE_NAME);
        return executeScript(scriptContent, defaultFile.getAbsolutePath(), callback);
    }

    public static boolean executeScript(String scriptContent, String scriptPath) {
        return executeScript(scriptContent, scriptPath, null);
    }

    public static boolean executeScript(String scriptContent, String scriptPath, LineCallback callback) {
        StringBuilder outputBuilder = new StringBuilder();
        Process process = null;
        File scriptFile = null;
        try {
            if (scriptPath == null || scriptPath.trim().isEmpty()) {
                throw new IllegalArgumentException("scriptPath is null or empty");
            }
            scriptFile = new File(scriptPath);
            try (FileOutputStream fos = new FileOutputStream(scriptFile)) {
                fos.write(scriptContent.getBytes(StandardCharsets.UTF_8));
                fos.flush();
            }
            boolean chmodOk = scriptFile.setExecutable(true, false);
            outputBuilder.append("[Script Path] ").append(scriptFile.getAbsolutePath()).append("\n");
            outputBuilder.append("[setExecutable] ").append(chmodOk).append("\n");
            ProcessBuilder processBuilder = new ProcessBuilder("sh", scriptFile.getAbsolutePath());
            processBuilder.redirectErrorStream(true);
            process = processBuilder.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    outputBuilder.append(line).append("\n");
                    if (callback != null) callback.onLine(line);
                }
            }
            int exitCode = process.waitFor();
            outputBuilder.append("\n[Exit Code: ").append(exitCode).append("]");
            if (callback != null) callback.onLine("[Exit Code: " + exitCode + "]");
        } catch (Exception e) {
            e.printStackTrace();
            outputBuilder.append("\n[Execution Error: ").append(e.getMessage()).append("]");
            if (callback != null) callback.onLine("[Execution Error: " + e.getMessage() + "]");
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return false;
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
        return true;
    }
}