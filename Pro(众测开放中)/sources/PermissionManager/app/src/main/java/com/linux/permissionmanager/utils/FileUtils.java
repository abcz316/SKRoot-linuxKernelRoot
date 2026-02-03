package com.linux.permissionmanager.utils;

import android.content.Context;
import android.content.res.AssetManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Environment;
import android.provider.DocumentsContract;
import android.provider.MediaStore;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Objects;
import java.util.stream.Stream;

public class FileUtils {
    public static String getRealPathFromURI(Context context, Uri uri) {
        String path = null;
        if (DocumentsContract.isDocumentUri(context, uri)) {
            String docId = DocumentsContract.getDocumentId(uri);
            String[] split = docId.split(":");
            String type = split[0];
            if ("primary".equalsIgnoreCase(type)) {
                path = Environment.getExternalStorageDirectory() + "/" + split[1];
            }
        } else if ("content".equalsIgnoreCase(uri.getScheme())) {
            String[] projection = {MediaStore.Images.Media.DATA};
            Cursor cursor = context.getContentResolver().query(uri, projection, null, null, null);
            if (cursor != null && cursor.moveToFirst()) {
                int columnIndex = cursor.getColumnIndexOrThrow(MediaStore.Images.Media.DATA);
                path = cursor.getString(columnIndex);
                cursor.close();
            }
        } else if ("file".equalsIgnoreCase(uri.getScheme())) {
            path = uri.getPath();
        }
        return path;
    }

    public static void deleteFile(File destFile) {
        try {
            if (destFile != null && destFile.exists()) destFile.delete();
        } catch (Exception ignore) {}
    }

    public static String formatFileSize(long size) {
        // 定义单位
        final long K = 1024;
        final long M = K * 1024;
        final long G = M * 1024;
        if (size >= G) {
            // 大于或等于GB
            return String.format("%.2f GB", (double) size / G);
        } else if (size >= M) {
            // 大于或等于MB
            return String.format("%.2f MB", (double) size / M);
        } else if (size >= K) {
            // 大于或等于KB
            return String.format("%.2f KB", (double) size / K);
        } else {
            // 小于KB
            return size + " B";
        }
    }
}
