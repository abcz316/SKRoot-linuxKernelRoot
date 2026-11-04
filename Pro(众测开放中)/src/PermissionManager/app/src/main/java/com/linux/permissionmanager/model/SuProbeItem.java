package com.linux.permissionmanager.model;

import android.graphics.drawable.Drawable;

public class SuProbeItem {
    private Drawable icon;
    private String appName;
    private String appPackageName;
    private int probeCount;
    private long lastProbeTimeS;
    private boolean isAuthorized;

    public SuProbeItem(Drawable icon, String appName, String appPackageName, int probeCount, long lastProbeTimeS, boolean isAuthorized) {
        this.icon = icon;
        this.appName = appName;
        this.appPackageName = appPackageName;
        this.probeCount = probeCount;
        this.lastProbeTimeS = lastProbeTimeS;
        this.isAuthorized = isAuthorized;
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

    public int getProbeCount() {
        return probeCount;
    }

    public void setProbeCount(int probeCount) {
        this.probeCount = probeCount;
    }

    public long getLastProbeTimeS() {
        return lastProbeTimeS;
    }

    public void setLastProbeTimeS(long lastProbeTimeS) {
        this.lastProbeTimeS = lastProbeTimeS;
    }

    public boolean isAuthorized() {
        return isAuthorized;
    }

    public void setAuthorized(boolean authorized) {
        isAuthorized = authorized;
    }
}
