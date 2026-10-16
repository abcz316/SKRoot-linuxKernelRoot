package com.android.zygotepreloadtools.utils;

import android.app.Activity;
import android.content.Intent;
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
}