package com.linux.permissionmanager.bridge;

import com.linux.permissionmanager.model.SkrModItem;
import com.linux.permissionmanager.model.SuAuthItem;

public final class NativeBridge {
    static { System.loadLibrary("permissionmanager"); }

    public static native String installSkrootEnv(String rootKey);
    public static native String uninstallSkrootEnv(String rootKey);
    public static native String getSkrootEnvState(String rootKey);
    public static native String getInstalledSkrootEnvVersion(String rootKey);
    public static native String getSdkVersion();
    
    public static native String testRoot(String rootKey);
    public static native String runRootCmd(String rootKey, String cmd);
    public static native String rootExecProcessCmd(String rootKey, String cmd);

    public static native String addSuAuth(String rootKey, String appPackageName);
    public static native String removeSuAuth(String rootKey, String appPackageName);
    public static native String getSuAuthList(String rootKey);
    public static native String clearSuAuthList(String rootKey);

    public static native String installSkrootModule(String rootKey, String zipFilePath);
    public static native String uninstallSkrootModule(String rootKey, String modUuid);
    public static native String getSkrootModuleList(String rootKey, boolean runningOnly);
    public static native String parseSkrootModuleDesc(String rootKey, String zipFilePath);
    public static native String openSkrootModuleWebUI(String rootKey, String modUuid);

    public static native String setBootFailProtectEnabled(String rootKey, boolean enable);
    public static native boolean isBootFailProtectEnabled(String rootKey);
    public static native String testSkrootBasics(String rootKey, String item);
    public static native String testSkrootDefaultModule(String rootKey, String name);

    public static native String setSkrootLogEnabled(String rootKey, boolean enable);
    public static native boolean isSkrootLogEnabled(String rootKey);
    public static native String readSkrootLog(String rootKey);


}