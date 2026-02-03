package com.linux.permissionmanager.model;

import android.graphics.drawable.Drawable;

public class SuAuthItem {
    private Drawable icon;
    private String appName;
    private String appPackageName;

    public SuAuthItem(Drawable icon, String appName, String appPackageName) {
        this.icon = icon;
        this.appName = appName;
        this.appPackageName = appPackageName;
    }

    public Drawable getIcon() {
        return icon;
    }

    public void setIcon(Drawable icon) {
        this.icon = icon;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public String getAppPackageName() {
        return appPackageName;
    }

    public void setAppPackageName(String appPackageName) {
        this.appPackageName = appPackageName;
    }

}
