package com.linux.permissionmanager.bridge;

public class NativeBridge {
    static {
        System.loadLibrary("permissionmanager");
    }

    public static native String testRoot(String rootKey);

    public static native String runRootCmd(String rootKey, String cmd);

    public static native String rootExecProcessCmd(String rootKey, String cmd);

    public static native String installSu(String rootKey);

    public static native String getLastSuFilePath();

    public static native String uninstallSu(String rootKey);

    public static native String autoSuEnvInject(String rootKey, String targetProcessCmdline);

    public static native String getAllCmdlineProcess(String rootKey);

    public static native String parasitePrecheckApp(String rootKey, String targetProcessCmdline);

    public static native String parasiteImplantApp(String rootKey, String targetProcessCmdline, String targetSoFullPath);

    public static native String parasiteImplantSuEnv(String rootKey, String targetProcessCmdline, String targetSoFullPath);

}
