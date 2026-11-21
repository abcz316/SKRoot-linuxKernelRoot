package com.linux.permissionmanager;

import android.content.Context;
import android.text.TextUtils;

import com.linux.permissionmanager.utils.FileUtils;

import org.json.JSONObject;

import java.io.File;

public class AppConfig {
    public static final String HOTLOAD_SHELL_PATH = "/sdcard/1.h";
    public static final String ZYGOTE_PRELOAD_TOOLS_PACKAGE = "com.android.zygotepreloadtools";
    public static final String ZYGOTE_PRELOAD_TOOLS_ENTRY_ACTIVITY = "com.linux.permissionmanager.EntryActivity";
    public static volatile String ENTRY_ADB_PAIRING_SERVICE_NAME = "com.linux.permissionmanager.localadb.EntryAdbPairingService";

    public static void init(Context context) {
        if (context == null) return;
        String jsonConfig = FileUtils.readTextFile(new File(context.getApplicationInfo().nativeLibraryDir, "libconfigjson.so").getAbsolutePath());
        if (TextUtils.isEmpty(jsonConfig)) return;
        try {
            JSONObject configJson = new JSONObject(jsonConfig);
            String serviceName = configJson.optString("entryAdbPairingServiceName", "");
            if (!TextUtils.isEmpty(serviceName)) ENTRY_ADB_PAIRING_SERVICE_NAME = serviceName;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
