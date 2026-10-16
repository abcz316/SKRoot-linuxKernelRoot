package com.linux.permissionmanager.model;

import android.graphics.drawable.Drawable;
import com.linux.permissionmanager.utils.AppCertUtils;

public class GenerateFakeAppConfig {
    public String pkgName = "", appName = "", originalAppName = "", launchActivity = "", versionName = "";
    public long versionCode;
    public boolean removeIcon;
    public Long fakeSize;
    public Drawable iconDrawable;
    public AppCertUtils.CertInfo certInfo = new AppCertUtils.CertInfo();
}