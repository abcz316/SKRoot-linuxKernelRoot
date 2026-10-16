package com.android.zygotepreloadtools.utils;

import android.app.Activity;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class FileUtils {
    public static String getPathFromUriByCopy(Context context, Uri uri) {
        if (uri == null) return null;
        String fileName = getFileNameFromUri(context, uri);
        if (fileName == null || fileName.isEmpty()) {
            fileName = "temp_file_" + System.currentTimeMillis() + ".zip";
        }
        File cacheDir = context.getCacheDir();
        File tempFile = new File(cacheDir, fileName);
        try (InputStream inputStream = context.getContentResolver().openInputStream(uri);
             FileOutputStream outputStream = new FileOutputStream(tempFile)) {
            if (inputStream == null) return null;
            byte[] buffer = new byte[8192];
            int length;
            while ((length = inputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, length);
            }
            outputStream.flush();
            return tempFile.getAbsolutePath();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 从 Uri 中提取真实文件名
     */
    private static String getFileNameFromUri(Context context, Uri uri) {
        String result = null;
        if ("content".equals(uri.getScheme())) {
            try (Cursor cursor = context.getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (index >= 0) {
                        result = cursor.getString(index);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (result == null) {
            result = uri.getPath();
            if (result != null) {
                int cut = result.lastIndexOf('/');
                if (cut != -1) {
                    result = result.substring(cut + 1);
                }
            }
        }
        return result;
    }

    public static boolean copyFile(File src, File dst) {
        if (src == null || !src.exists() || !src.isFile()) return false;
        File parent = dst.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) return false;

        try (InputStream in = new FileInputStream(src);
             FileOutputStream out = new FileOutputStream(dst)) {
            byte[] buf = new byte[8192];
            int len;
            while ((len = in.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
            out.flush();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public static void deleteFile(File destFile) {
        try {
            if (destFile != null && destFile.exists()) destFile.delete();
        } catch (Exception ignore) {}
    }
}
