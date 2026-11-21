package com.linux.permissionmanager.hotload;

import android.app.Activity;
import android.text.TextUtils;

import com.linux.permissionmanager.AppConfig;
import com.linux.permissionmanager.helper.dirtyfrag.ExploitRunner;
import com.linux.permissionmanager.localadb.AdbPairingNotification;
import com.linux.permissionmanager.localadb.LocalAdbHelper;
import com.linux.permissionmanager.model.HotloadMethod;
import com.linux.permissionmanager.repack.ApkGenerator;
import com.linux.permissionmanager.utils.ApkInstallUtils;
import com.linux.permissionmanager.utils.AppLaunchUtils;
import com.linux.permissionmanager.utils.DialogUtils;
import com.linux.permissionmanager.utils.FileUtils;
import com.linux.permissionmanager.utils.ShellUtils;

import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

public final class HotloadLauncher {

    private HotloadLauncher() {}

    public static boolean precheck(Activity activity, String rootKey, HotloadMethod method, String script, LocalAdbHelper localAdb) {
        if (method == HotloadMethod.MAGICA) {
            if (AppLaunchUtils.launchApp(activity, AppConfig.ZYGOTE_PRELOAD_TOOLS_PACKAGE, AppConfig.ZYGOTE_PRELOAD_TOOLS_ENTRY_ACTIVITY)) return false;
            if (!ApkInstallUtils.getInstallPermission(activity)) {
                DialogUtils.showNeedPermissionDialog(activity, "安装应用权限");
                return false;
            }
            installMagicaApk(activity, script, rootKey);
            return false;
        } else if (method == HotloadMethod.CVE_2026_98260) {
            if (localAdb.hasPairedConnection()) return true;
            if (!AdbPairingNotification.ensureNotificationsAvailable(activity)) return false;
            localAdb.beginNotificationPairing();
            return false;
        }
        return true;
    }

    public static void launch(Activity activity, HotloadMethod method, String script, Consumer<DialogUtils.LogDialog> onFinished) {
        if (TextUtils.isEmpty(script)) return;
        DialogUtils.LogDialog logDlg = new DialogUtils.LogDialog(activity, "正在加载热启动补丁，预计需要 1 分钟");
        logDlg.appendLine("[开始执行热启动补丁]");
        if (method == HotloadMethod.SHELL) {
            launchShell(activity, script, logDlg, onFinished);
        } else if (method == HotloadMethod.CVE_2026_43499) {
            launchCve43499(activity, script, logDlg, onFinished);
        } else if (method == HotloadMethod.CVE_2026_43284) {
            launchCve43284(activity, script, logDlg, onFinished);
        } else if (method == HotloadMethod.CVE_2026_98260) {
            launchCve98260(activity, script, logDlg, onFinished);
        }
    }

    private static void launchShell(Activity activity, String script, DialogUtils.LogDialog logDlg, Consumer<DialogUtils.LogDialog> onFinished) {
        new Thread(() -> {
            ShellUtils.executeScript(activity, script, logDlg::appendLine);
            if (onFinished != null) onFinished.accept(logDlg);
        }).start();
    }

    private static void launchCve43499(Activity activity, String script, DialogUtils.LogDialog logDlg, Consumer<DialogUtils.LogDialog> onFinished) {
        new Thread(() -> {
            int methodVer = extractConfigInt(script, "METHOD_VER");
            File ghostSo = new File(activity.getApplicationInfo().nativeLibraryDir, methodVer == 2 ? "libcve2026_43499_ghostlock_v2.so" : "libcve2026_43499_ghostlock_v1.so");
            ShellUtils.executeScript(activity, GuideScripts.getCve2026_43499(ghostSo) + script, logDlg::appendLine);
            if (onFinished != null) onFinished.accept(logDlg);
        }).start();
    }

    private static void launchCve43284(Activity activity, String script, DialogUtils.LogDialog logDlg, Consumer<DialogUtils.LogDialog> onFinished) {
        new Thread(() -> {
            final String[] koPathHolder = new String[1];
            ShellUtils.executeScript(activity, script, line -> {
                logDlg.appendLine(line);
                if (line.startsWith("KO_PATH=")) koPathHolder[0] = line.substring("KO_PATH=".length()).trim();
            });
            logDlg.appendLine("dfroot rc=" + ExploitRunner.run(activity, logDlg::appendLine, koPathHolder[0]) + "\n");
            if (onFinished != null) onFinished.accept(logDlg);
        }).start();
    }

    private static void launchCve98260(Activity activity, String script, DialogUtils.LogDialog logDlg, Consumer<DialogUtils.LogDialog> onFinished) {
        File ghostSo = new File(activity.getApplicationInfo().nativeLibraryDir, "libcve2026_98260_ghostkey_v1.so");
        LocalAdbHelper localAdb = new LocalAdbHelper(activity);
        localAdb.runScriptAsShell(GuideScripts.getCve2026_98260(ghostSo, script), logDlg::appendLine, () -> { if (onFinished != null) onFinished.accept(logDlg); }, logDlg::dismiss);
    }

    private static void installMagicaApk(Activity activity, String script, String rootKey) {
        new Thread(() -> {
            try {
                String packageName = activity.getPackageName();
                String activityName = AppLaunchUtils.getLauncherActivityName(activity);
                File apk = generateZygotePreloadTools(activity, script, packageName, activityName, AppConfig.ZYGOTE_PRELOAD_TOOLS_PACKAGE, "越狱临时启动器" + getShortKey(rootKey));
                activity.runOnUiThread(() -> ApkInstallUtils.requestInstall(activity, apk));
            } catch (Exception e) {
                activity.runOnUiThread(() -> DialogUtils.showMsgDlg(activity, "生成失败", "生成失败：" + e.getMessage(), null));
            }
        }, "apk-generate-worker").start();
    }

    private static String getShortKey(String key) { return key.length() >= 5 ? key.substring(0, 5) : key; }

    // 读取脚本头部的 #KEY=VALUE，例如 #ROOT_KEY=xxx、#METHOD=CVE-2026-98260
    public static String getConfigValue(String text, String key) {
        if(TextUtils.isEmpty(text)) return "";
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("(?m)^\\s*#.*?\\b" + java.util.regex.Pattern.quote(key) + "\\s*=\\s*(\\S+)");
        java.util.regex.Matcher matcher = pattern.matcher(text);
        return matcher.find() ? matcher.group(1).trim() : "";
    }

    private static int extractConfigInt(String text, String key) {
        String value = getConfigValue(text, key);
        if (TextUtils.isEmpty(value)) return 0;
        try { return Integer.parseInt(value); } catch (NumberFormatException e) { return 0; }
    }

    private static File generateZygotePreloadTools(Activity activity, String script, String goBackPackageName, String goBackActivity, String newPackageName, String newAppName) throws Exception {
        File sourceApk = FileUtils.copyAssetToCache(activity, "ZygotePreloadTools.apk", ".apk");
        File outputDir = new File(activity.getFilesDir(), "generated-apks");
        FileUtils.clearDirectory(outputDir);
        try {
            JSONObject json = new JSONObject();
            json.put("goBackPackageName", goBackPackageName);
            json.put("goBackActivityName", goBackActivity);
            json.put("scriptSuccessTip", "加载完成！请返回SKRoot APP继续安装SKRoot环境");
            json.put("scriptErrorTip", "加载出错，请重试或保存日志反馈");
            String jsonStr = json.toString();
            Map<String, byte[]> replacements = new LinkedHashMap<>();
            replacements.put("lib/arm64-v8a/libsh.so", script.getBytes(StandardCharsets.UTF_8));
            replacements.put("lib/arm64-v8a/libconfigjson.so", jsonStr.getBytes(StandardCharsets.UTF_8));
            ApkGenerator.GenerateOptions options = new ApkGenerator.GenerateOptions();
            options.sourceApk = sourceApk;
            options.soReplacements = replacements;
            options.newPackageName = newPackageName;
            options.newAppName = newAppName;
            options.outputApk = new File(outputDir, "zygote-clone" + System.nanoTime() + ".apk");
            return ApkGenerator.generate(activity, options);
        } finally {
            sourceApk.delete();
        }
    }
}
