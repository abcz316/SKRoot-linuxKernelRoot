package com.android.zygotepreloadtools;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

@RequiresApi(api = Build.VERSION_CODES.Q)
public class AppZygotePreload implements ZygotePreload {
    @Override
    public void doPreload(@NonNull ApplicationInfo appInfo) {
        System.loadLibrary("magica");
    }
}