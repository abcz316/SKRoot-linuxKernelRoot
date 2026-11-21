package com.linux.permissionmanager.localadb;

import android.app.RemoteInput;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

public final class AdbPairingReceiver extends BroadcastReceiver {

    public static final String ACTION_SUBMIT_PAIRING_CODE = "com.linux.permissionmanager.localadb.action.SUBMIT_PAIRING_CODE";
    public static final String ACTION_STOP_SESSION = "com.linux.permissionmanager.localadb.action.STOP_SESSION";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        if (ACTION_STOP_SESSION.equals(intent.getAction())) {
            startPairingService(context, LocalAdbHelper.buildPairingServiceIntent(context, AdbPairingService.ACTION_STOP));
            return;
        }
        if (!ACTION_SUBMIT_PAIRING_CODE.equals(intent.getAction())) return;
        Bundle remoteInputResults = RemoteInput.getResultsFromIntent(intent);
        CharSequence pairingCodeInput = remoteInputResults == null ? null : remoteInputResults.getCharSequence(AdbPairingNotification.REMOTE_INPUT_KEY);
        String pairingCode = pairingCodeInput == null ? "" : pairingCodeInput.toString().trim();
        Intent serviceIntent = LocalAdbHelper.buildPairingServiceIntent(context, AdbPairingService.ACTION_SUBMIT_CODE);
        if (serviceIntent == null) {
            Toast.makeText(context.getApplicationContext(), "未找到配对服务，请重新安装APP后重试", Toast.LENGTH_LONG).show();
            return;
        }
        serviceIntent.putExtra(AdbPairingService.EXTRA_PAIRING_CODE, pairingCode);
        startPairingService(context, serviceIntent);
    }

    private void startPairingService(Context context, Intent intent) {
        if (intent == null) {
            Toast.makeText(context.getApplicationContext(), "未找到配对服务，请重新安装APP后重试", Toast.LENGTH_LONG).show();
            return;
        }
        try {
            context.startForegroundService(intent);
        } catch (RuntimeException e) {
            // 前台服务启动被拦截时通知栏不会给出任何反馈，这里兜一个可见提示。
            Log.e("LocalAdb", "无法转发通知栏配对操作到前台服务", e);
            Toast.makeText(context.getApplicationContext(), "配对服务启动失败，请打开 APP 后重试", Toast.LENGTH_LONG).show();
        }
    }
}
