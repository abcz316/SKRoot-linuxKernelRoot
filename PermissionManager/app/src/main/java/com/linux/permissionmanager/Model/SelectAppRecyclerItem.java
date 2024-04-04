package com.linux.permissionmanager.Model;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.graphics.drawable.Drawable;

public class SelectAppRecyclerItem {
    private PackageInfo packageInfo;

    public SelectAppRecyclerItem(PackageInfo packageInfo){
        this.packageInfo = packageInfo;
    }

    public PackageInfo getPackageInfo() {
        return packageInfo;
    }

    public String getShowName(Context ctx) {
        String showName = this.packageInfo.applicationInfo.loadLabel(ctx.getPackageManager()).toString();
        return showName;
    }
    public String getPackageName() {
        String packageName = this.packageInfo.applicationInfo.packageName;
        return packageName;
    }
    public Drawable getDrawable(Context ctx) {
        Drawable icon =  this.packageInfo.applicationInfo.loadIcon(ctx.getPackageManager());
        return icon;
    }

}
