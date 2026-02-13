package com.linux.permissionmanager.model;

import android.text.TextUtils;

public class SkrModInstalledItem {
    private String name;
    private String desc;
    private String ver;
    private String uuid;
    private String author;
    private String updateJson;
    private String miniSdk;
    private boolean webUi;
    private boolean isRunning;

    private SkrModUpdateInfo updateInfo;

    public SkrModInstalledItem(String name, String desc, String ver, String uuid, String author, String updateJson, String miniSdk, boolean webUi, boolean isRunning) {
        this.name = name;
        this.desc = desc;
        this.ver = ver;
        this.uuid = uuid;
        this.author = author;
        this.updateJson = updateJson;
        this.miniSdk = miniSdk;
        this.webUi = webUi;
        this.isRunning = isRunning;
        this.updateInfo = null;   // 默认无更新信息
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDesc() {
        return desc;
    }

    public void setDesc(String desc) {
        this.desc = desc;
    }

    public String getVer() {
        return ver;
    }

    public void setVer(String ver) {
        this.ver = ver;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public String getUpdateJson() {
        return updateJson;
    }

    public void setUpdateJson(String updateJson) { this.updateJson = updateJson; }

    public String getMiniSdk() {
        return miniSdk;
    }

    public void setMiniSdk(String miniSdk) {
        this.miniSdk = miniSdk;
    }

    public boolean isWebUi() {
        return webUi;
    }

    public void setWebUi(boolean webUi) {
        this.webUi = webUi;
    }

    public boolean isRunning() {
        return isRunning;
    }

    public void setRunning(boolean running) {
        isRunning = running;
    }

    public SkrModUpdateInfo getUpdateInfo() {
        return updateInfo;
    }

    public void setUpdateInfo(SkrModUpdateInfo updateInfo) {
        this.updateInfo = updateInfo;
    }

    public boolean hasChangelog() {
        return updateInfo != null && !TextUtils.isEmpty(updateInfo.getChangelogUrl());
    }
}
