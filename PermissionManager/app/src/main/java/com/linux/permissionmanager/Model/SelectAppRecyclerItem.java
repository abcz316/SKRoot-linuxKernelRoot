package com.linux.permissionmanager.Model;

import android.graphics.drawable.Drawable;

public class SelectAppRecyclerItem {
    private Drawable icon=null;
    private String showName;
    private String packageName;

    public SelectAppRecyclerItem(Drawable icon, String showName, String packageName){
        this.icon=icon;
        this.showName = showName;
        this.packageName = packageName;
    }

    public Drawable getIcon() {
        return icon;
    }

    public void setIcon(Drawable icon) {
        this.icon = icon;
    }

    public String getShowName() {
        return showName;
    }

    public void setShowName(String showName) {
        this.showName = showName;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

}
