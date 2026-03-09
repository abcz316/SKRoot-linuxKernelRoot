package com.linux.permissionmanager.utils;

import android.app.Activity;
import android.content.pm.PackageInfo;

import java.util.List;

public class GetAppListPermissionHelper {
    public static boolean getPermissions(Activity activity) {
        List<PackageInfo> packages = activity.getPackageManager().getInstalledPackages(0);
        return packages.size() > 0;
    }
}
