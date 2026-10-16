package com.linux.permissionmanager.utils;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;

import androidx.core.content.FileProvider;

import java.io.File;

public final class ApkInstallUtils {
    private ApkInstallUtils() {}

    // 提前检查安装权限，未授权则跳转系统授权页面
    public static boolean getInstallPermission(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return true;
        if (context.getPackageManager().canRequestPackageInstalls()) return true;

        Intent intent = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES);
        intent.setData(Uri.parse("package:" + context.getPackageName()));
        if (!(context instanceof Activity)) intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

        context.startActivity(intent);
        return false;
    }

    // 打开系统 APK 安装确认界面
    public static boolean requestInstall(Context context, File apk) {
        if (apk == null || !apk.isFile() || apk.length() == 0) throw new IllegalArgumentException("安装文件不存在或为空");

        if (!getInstallPermission(context)) return false;
        Uri uri = FileProvider.getUriForFile(context, context.getPackageName() + ".apkfileprovider", apk);
        Intent install = new Intent(Intent.ACTION_VIEW);
        install.setDataAndType(uri, "application/vnd.android.package-archive");
        install.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        if (!(context instanceof Activity)) install.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

        try {
            context.startActivity(install);
        } catch (ActivityNotFoundException e) {
            throw new IllegalStateException("系统中没有能处理 APK 安装的 Activity", e);
        }
        return true;
    }
}