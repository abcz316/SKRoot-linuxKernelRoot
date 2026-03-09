package com.linux.permissionmanager.model;

public class SkrModMarketItem {
    private String chnName;
    private String engName;
    private String desc;
    private String ver;
    private String uuid;
    private String author;
    private String updateDate;
    private String sourceUrl;
    private String downloadUrl;
    private String downloadChnAlert;
    private String downloadEngAlert;

    public String getChnName() {
        return chnName;
    }

    public void setChnName(String chnName) {
        this.chnName = chnName;
    }

    public String getEngName() {
        return engName;
    }

    public void setEngName(String engName) {
        this.engName = engName;
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

    public String getUpdateDate() {
        return updateDate;
    }

    public void setUpdateDate(String updateDate) {
        this.updateDate = updateDate;
    }

    public String getSourceUrl() {
        return sourceUrl;
    }

    public void setSourceUrl(String sourceUrl) {
        this.sourceUrl = sourceUrl;
    }

    public String getDownloadUrl() {
        return downloadUrl;
    }

    public void setDownloadUrl(String downloadUrl) {
        this.downloadUrl = downloadUrl;
    }

    public String getDownloadChnAlert() {
        return downloadChnAlert;
    }

    public void setDownloadChnAlert(String downloadChnAlert) {
        this.downloadChnAlert = downloadChnAlert;
    }

    public String getDownloadEngAlert() {
        return downloadEngAlert;
    }

    public void setDownloadEngAlert(String downloadEngAlert) {
        this.downloadEngAlert = downloadEngAlert;
    }

    public SkrModMarketItem(String chnName, String engName, String desc, String ver, String uuid, String author, String updateDate, String sourceUrl, String downloadUrl, String downloadChnAlert, String downloadEngAlert) {
        this.chnName = chnName;
        this.engName = engName;
        this.desc = desc;
        this.ver = ver;
        this.uuid = uuid;
        this.author = author;
        this.updateDate = updateDate;
        this.sourceUrl = sourceUrl;
        this.downloadUrl = downloadUrl;
        this.downloadChnAlert = downloadChnAlert;
        this.downloadEngAlert = downloadEngAlert;
    }
}
