package com.linux.permissionmanager.localadb;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import java.util.Locale;
import java.util.UUID;

import com.linux.permissionmanager.AppConfig;
import com.linux.permissionmanager.utils.DialogUtils;

public final class LocalAdbHelper {
    // 无线调试重启后端口就会变，只缓存本次运行的连接，APP 重启后重新配对。
    private static volatile int connectedPort = 0;

    private final Activity activity;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    public LocalAdbHelper(Activity activity) {
        this.activity = activity;
    }

    public static void onAdbConnected(int port) {
        if (port > 0) connectedPort = port;
    }

    public static void onAdbDisconnected() {
        connectedPort = 0;
    }

    public boolean hasPairedConnection() {
        return connectedPort > 0;
    }

    public static Intent buildPairingServiceIntent(Context context, String action) {
        return new Intent().setClassName(context, AppConfig.ENTRY_ADB_PAIRING_SERVICE_NAME).setAction(action);
    }

    public static void stopPairing(Activity activity) {
        connectedPort = 0;
        if (!AdbPairingService.isServiceRunning()) return;
        try {
            Intent intent = buildPairingServiceIntent(activity, AdbPairingService.ACTION_STOP);
            if (intent != null) activity.startService(intent);
        } catch (Exception ignored) {}
    }

    // 端口每次都变，复用旧连接只会得到 Connection refused，所以每次都走通知栏配对。
    public void beginNotificationPairing() {
        if (activity.isFinishing() || activity.isDestroyed()) return;
        if (!AdbPairingNotification.ensureNotificationsAvailable(activity)) return;
        startPairingService();
        showPairingReadyDialog();
    }

    private void startPairingService() {
        Intent intent = buildPairingServiceIntent(activity, AdbPairingService.ACTION_START);
        if (intent == null) {
            DialogUtils.showMsgDlg(activity, "无法启动配对通知", "当前安装包缺少配对服务声明，请重新安装APP。", null);
            return;
        }
        intent.putExtra(AdbPairingService.EXTRA_SESSION_ID, UUID.randomUUID().toString());
        try {
            activity.startForegroundService(intent);
        } catch (Exception e) {
            DialogUtils.showMsgDlg(activity, "无法启动配对通知", "请重试一次；若仍然失败，请重启APP。", null);
        }
    }

    private void showPairingReadyDialog() {
        DialogUtils.showMsgDlg(activity, "配对指引",
                "1. 进入「开发者选项」→「无线调试」→「使用配对码配对设备」，并保持该页面打开\n"
                + "2. 下拉通知栏，点击「输入配对码」，填写页面上显示的 6 位数字", null);
    }

    public void runScriptAsShell(final String script, final AdbManager.LineCallback lineCallback, final Runnable onFinished, final Runnable onNeedPairing) {
        AdbManager.LineCallback uiLineCallback = line -> {
            if (lineCallback != null) mainHandler.post(() -> lineCallback.onLine(line));
        };
        final int port = connectedPort;
        if (port <= 0) {
            uiLineCallback.onLine("尚未完成配对，请先在通知栏输入配对码。");
            mainHandler.post(() -> {
                if (onNeedPairing != null) onNeedPairing.run();
                beginNotificationPairing();
            });
            return;
        }
        new Thread(() -> {
            try {
                AdbManager manager = new AdbManager(activity.getApplicationContext());
                AdbManager.CommandResult result = manager.executeScriptAsShell(port, script, uiLineCallback);
                if (!result.isSuccess()) {
                    if (looksLikeConnectFailure(result.output)) {
                        onAdbDisconnected();
                        uiLineCallback.onLine("连接已失效，正在重新发起配对。\n请下拉通知栏点击「输入配对码」，配对成功后再点击「确定」。");
                        mainHandler.post(() -> {
                            if (onNeedPairing != null) onNeedPairing.run();
                            beginNotificationPairing();
                        });
                        return;
                    }
                    uiLineCallback.onLine("[退出码 " + result.exitCode + "]");
                }
            } catch (Exception e) {
                uiLineCallback.onLine("执行失败，请重试。");
            }
            if (onFinished != null) mainHandler.post(onFinished);
        }, "local-adb-shell").start();
    }

    private static boolean looksLikeConnectFailure(String output) {
        if (output == null) return false;
        String text = output.toLowerCase(Locale.ROOT);
        return text.contains("failed to connect")
                || text.contains("unable to connect")
                || text.contains("cannot connect")
                || text.contains("connection refused")
                || text.contains("device offline")
                || text.contains("unauthorized")
                || text.contains("no devices");
    }
}
