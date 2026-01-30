package com.linux.permissionmanager.utils;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.text.TextUtils;
import android.widget.Toast;

public final class UrlIntentUtils {
    private UrlIntentUtils() {}

    /** 在外部浏览器打开链接；支持传 "example.com" 自动补全 https:// */
    public static boolean openUrl(Context context, String url) {
        if (context == null) return false;
        if (TextUtils.isEmpty(url)) {
            Toast.makeText(context, "链接为空", Toast.LENGTH_SHORT).show();
            return false;
        }

        String u = url.trim();
        // 没有 scheme 的话补 https://
        if (!u.startsWith("http://") && !u.startsWith("https://")) {
            u = "https://" + u;
        }

        Uri uri = Uri.parse(u);
        Intent intent = new Intent(Intent.ACTION_VIEW, uri);

        // 非 Activity context 需要 NEW_TASK
        if (!(context instanceof Activity)) {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        }

        try {
            context.startActivity(intent);
            return true;
        } catch (ActivityNotFoundException e) {
            Toast.makeText(context, "没有可打开链接的应用", Toast.LENGTH_SHORT).show();
            return false;
        } catch (Exception e) {
            Toast.makeText(context, "打开链接失败", Toast.LENGTH_SHORT).show();
            return false;
        }
    }
}
