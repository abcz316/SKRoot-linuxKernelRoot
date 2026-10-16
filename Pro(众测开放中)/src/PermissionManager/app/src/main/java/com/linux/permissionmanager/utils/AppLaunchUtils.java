package com.linux.permissionmanager.utils;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.util.Log;

public final class AppLaunchUtils {

    private static final String TAG = "AppLaunchUtils";

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
}