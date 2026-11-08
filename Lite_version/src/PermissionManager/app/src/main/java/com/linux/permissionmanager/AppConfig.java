package com.linux.permissionmanager;

import android.content.Context;
import android.content.pm.ApplicationInfo;

import com.linux.permissionmanager.utils.FileUtils;

import org.json.JSONObject;

import java.io.File;

public class AppConfig {

    private static AppConfig sInstance;

    public static final String HOTLOAD_SHELL_PATH = "/sdcard/1.h";
    public static final String ZYGOTE_PRELOAD_TOOLS_PACKAGE = "com.android.zygotepreloadtools";
    public static final String ZYGOTE_PRELOAD_TOOLS_MAIN_ACTIVITY = "com.android.zygotepreloadtools.MainActivity";
}