package com.linux.permissionmanager.utils;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.Settings;

import androidx.core.app.ActivityCompat;

public class GetSdcardPermissionsHelper {
    public static boolean getPermissions(Activity activity, Context ctx, String packageName) {
//        普通权限：只需要在清单文件中注册即可
//        危险权限(Android 6.0 之后)：需要在代码中动态申请，以弹系统 Dialog 的形式进行请求
//        特殊权限(Android 11(含) 之后)：需要在代码中动态申请，以跳系统 Activity 的形式进行请求
        //android版本大于等于11
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {//必须要MANAGE_EXTERNAL_STORAGE权限，但Google Play Console审核不通过
            // 先判断有没有权限
            if (Environment.isExternalStorageManager()) {
                //有权限
                return true;
            } else {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + packageName));
                activity.startActivityForResult(intent, 0);
                return false;
            }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            int permission_write= ActivityCompat.checkSelfPermission(ctx,
                    Manifest.permission.WRITE_EXTERNAL_STORAGE);
            int permission_read=ActivityCompat.checkSelfPermission(ctx,
                    Manifest.permission.READ_EXTERNAL_STORAGE);
            if(permission_write!= PackageManager.PERMISSION_GRANTED
                    || permission_read!= PackageManager.PERMISSION_GRANTED){
                //申请权限，特征码自定义为0，可在回调时进行相关判断
                activity.requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE,Manifest.permission.READ_EXTERNAL_STORAGE},0);
                return false;
            } else {
                //有权限后需要处理的功能
                return true;
            }
        } else {
            //有权限后需要处理的功能
            return true;
        }
    }
}
