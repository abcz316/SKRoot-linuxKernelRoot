package com.linux.permissionmanager.utils;

import android.content.Context;
import android.content.pm.PackageManager;

public final class AppInstallUtils {
    private AppInstallUtils() {}

    public static boolean isAppInstalled(Context context, String packageName) {
        if (context == null || packageName == null || packageName.isEmpty()) return false;
        try {
            context.getPackageManager().getPackageInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }
}
