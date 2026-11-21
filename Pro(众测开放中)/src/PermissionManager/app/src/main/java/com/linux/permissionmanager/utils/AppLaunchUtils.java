package com.linux.permissionmanager.utils;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import java.util.Random;

public final class AppLaunchUtils {

    private static final String TAG = "AppLaunchUtils";

    /** 目标 APP 没有任何 Service 时，用这些常见名字随机拼一个伪装 Service 类名。 */
    private static final String[] FAKE_SERVICE_NAMES = {
            "BroadcastService", "BootService", "DownloadService", "UploadService", "SyncService",
            "PushService", "MessageService", "HeartbeatService", "KeepAliveService", "PollingService",
            "LocationService", "BluetoothService", "NetworkMonitorService", "MusicPlayService",
            "AudioRecordService", "StepCountService", "NotificationService", "UpdateService",
            "LogUploadService", "FileTransferService", "CleanService", "ScreenRecordService",
            "ForegroundService", "TimeService", "AlarmService", "ReminderService", "SmsService",
            "CallService", "ContactSyncService", "PhotoBackupService"
    };

    private static final Random RANDOM = new Random();

    private AppLaunchUtils() {}

    public static boolean launchApp(Activity activity, String packageName, String activityName) {
        if (activity == null || packageName == null || packageName.isEmpty() || activityName == null || activityName.isEmpty()) return false;

        try {
            Intent intent = new Intent(Intent.ACTION_MAIN);
            intent.addCategory(Intent.CATEGORY_LAUNCHER);
            intent.setClassName(packageName, activityName);
            // 使用目标 APP 自己的任务栈
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED);
            activity.startActivity(intent);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to launch: " + packageName + "/" + activityName, e);
            return false;
        }
    }

    public static String getLauncherActivityName(Context context) {
        if (context == null) return null;

        try {
            Intent intent = context.getPackageManager().getLaunchIntentForPackage(context.getPackageName());
            if (intent == null || intent.getComponent() == null) return null;
            return intent.getComponent().getClassName();
        } catch (Exception e) {
            Log.e(TAG, "Failed to get launcher activity name", e);
            return null;
        }
    }

    public static String getLauncherActivityName(Context context, String packageName) {
        if (context == null || packageName == null || packageName.isEmpty()) return null;
        try {
            PackageManager pm = context.getPackageManager();
            Intent intent = pm.getLaunchIntentForPackage(packageName);
            if (intent == null || intent.getComponent() == null) return null;
            return intent.getComponent().getClassName();
        } catch (Exception e) {
            Log.e(TAG, "Failed to get launcher activity name: " + packageName, e);
            return null;
        }
    }

    @SuppressWarnings("deprecation")
    public static String getAppServiceName(Context context, String packageName) {
        if (context == null || packageName == null || packageName.isEmpty()) return null;

        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo info = pm.getPackageInfo(packageName, PackageManager.GET_SERVICES);
            if (info.services != null && info.services.length > 0) return info.services[0].name;
        } catch (Exception e) {
            // 应用不存在，或当前 APP 没有查询该应用的权限
            Log.w(TAG, "Failed to get service name: " + packageName, e);
        }
        return packageName + "." + FAKE_SERVICE_NAMES[RANDOM.nextInt(FAKE_SERVICE_NAMES.length)];
    }
}