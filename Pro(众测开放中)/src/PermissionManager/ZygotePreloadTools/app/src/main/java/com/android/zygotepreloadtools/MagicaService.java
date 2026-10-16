package com.android.zygotepreloadtools;

import android.app.Service;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.IBinder;
import android.system.Os;
import android.util.Log;

import androidx.annotation.Nullable;

import com.android.zygotepreloadtools.utils.FileUtils;

import java.io.File;

public class MagicaService extends Service {
    private static final String TAG = "Magica";
    private Process process;
    private final IRemoteService.Stub binder = new IRemoteService.Stub() {
        @Override
        public IRemoteProcess getRemoteProcess() {
            return new RemoteProcessHolder(process);
        }
    };

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        boolean toolsCreated = false;
        try {
            Os.setuid(0);
            createResetpropTools();
            toolsCreated = true;
            process = Runtime.getRuntime().exec(new String[]{
                    "/system/bin/sh",
                    "-c",
                            "TMP=/data/adb/temp_sk.sh; " +
                            "echo \"[MAGICA] TMP=$TMP\" >&2; " +
                            "cleanup(){ rm -f \"$TMP\"; }; " +
                            "trap cleanup EXIT HUP INT TERM; " +
                            "rm -f \"$TMP\" 2>/dev/null; " +
                            ": > \"$TMP\" 2>/dev/null || { " +
                            "  echo \"[MAGICA] create temp script failed\" >&2; " +
                            "  echo \"[MAGICA] uid=$(id -u)\" >&2; " +
                            "  ls -ld /data /data/adb 2>&1 >&2; " +
                            "  exit 111; " +
                            "}; " +
                            "echo \"[MAGICA] temp script created\" >&2; " +
                            "cat > \"$TMP\"; " +
                            "rc=$?; " +
                            "echo \"[MAGICA] cat rc=$rc\" >&2; " +
                            "[ \"$rc\" -eq 0 ] || exit \"$rc\"; " +
                            "chmod 700 \"$TMP\" 2>/dev/null || true; " +
                            "/system/bin/sh \"$TMP\"; " +
                            "rc=$?; " +
                            "cleanup; " +
                            "trap - EXIT HUP INT TERM; " +
                            "exit \"$rc\""
            });
            Log.d(TAG, "onBind: root shell created");
            return binder;
        } catch (Throwable t) {
            Log.e(TAG, "onBind failed", t);
            if (process != null) {
                try {
                    process.destroy();
                } catch (Throwable ignore) {}
                process = null;
            }
            if (toolsCreated) deleteResetpropTools();
            return null;
        }
    }

    @Override
    public boolean onUnbind(Intent intent) {
        destroyProcessQuietly();
        deleteResetpropTools();
        return super.onUnbind(intent);
    }

    @Override
    public void onDestroy() {
        destroyProcessQuietly();
        deleteResetpropTools();
        super.onDestroy();
    }

    private void destroyProcessQuietly() {
        if (process != null) {
            try {
                process.destroy();
            } catch (Throwable ignore) {
            }
            process = null;
        }
    }

    private void createResetpropTools() {
        ApplicationInfo appInfo = getApplicationInfo();
        File srcFile = new File(appInfo.nativeLibraryDir, "libresetprop.so");
        File dstFile = new File("/data/adb/resetprop");
        FileUtils.copyFile(srcFile, dstFile);
    }

    private void deleteResetpropTools() {
        File dstFile = new File("/data/adb/resetprop");
        FileUtils.deleteFile(dstFile);
    }
}