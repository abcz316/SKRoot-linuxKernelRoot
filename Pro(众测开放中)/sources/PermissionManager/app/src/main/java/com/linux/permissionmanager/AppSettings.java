package com.linux.permissionmanager;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.Collections;
import java.util.Set;

public class AppSettings {
    private static SharedPreferences preferences;

    public static void init(Context context) {
        if (preferences == null) {
            preferences = context.getSharedPreferences("AppSettings", Context.MODE_PRIVATE);
        }
    }

    public static void setBoolean(String key, boolean value) {
        preferences.edit().putBoolean(key, value).apply();
    }

    public static boolean getBoolean(String key, boolean defaultValue) {
        try {
            return preferences.getBoolean(key, defaultValue);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return defaultValue;
    }

    public static void setString(String key, String value) {
        preferences.edit().putString(key, value).apply();
    }

    public static String getString(String key, String defaultValue) {
        try {
            return preferences.getString(key, defaultValue);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return defaultValue;
    }

    public static void setInt(String key, int value) {
        preferences.edit().putInt(key, value).apply();
    }

    public static int getInt(String key, int defaultValue) {
        try {
            return preferences.getInt(key, defaultValue);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return defaultValue;
    }

    public static void setStringSet(String key, Set<String> value) {
        preferences.edit().putStringSet(key, value).apply();
    }

    public static Set<String> getStringSet(String key, Set<String> defaultValue) {
        try {
            return preferences.getStringSet(key, defaultValue);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return defaultValue != null ? defaultValue : Collections.emptySet();
    }
}
