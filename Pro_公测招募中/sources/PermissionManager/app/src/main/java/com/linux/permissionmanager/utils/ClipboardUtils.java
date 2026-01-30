package com.linux.permissionmanager.utils;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;

public class ClipboardUtils {
    public static void copyText(Context ctx, String text) {
        //获取剪贴板管理器：
        ClipboardManager cm = (ClipboardManager)ctx.getSystemService(Context.CLIPBOARD_SERVICE);
        // 创建普通字符型ClipData
        ClipData mClipData = ClipData.newPlainText("Label", text);
        // 将ClipData内容放到系统剪贴板里。
        cm.setPrimaryClip(mClipData);
    }
}
