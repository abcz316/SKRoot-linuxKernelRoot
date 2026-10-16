
package com.android.zygotepreloadtools.utils;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;

public final class AppUninstallUtils {
    private AppUninstallUtils() {}
    public static boolean uninstallSelf(Context context) {
        if (context == null) return false;
        try {
            Intent intent = new Intent(Intent.ACTION_UNINSTALL_PACKAGE);
            intent.setData(Uri.parse("package:" + context.getPackageName()));

            if (!(context instanceof Activity)) {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            }

            context.startActivity(intent);
            return true;
        } catch (ActivityNotFoundException | SecurityException e) {
            e.printStackTrace();
            return false;
        }
    }
}
