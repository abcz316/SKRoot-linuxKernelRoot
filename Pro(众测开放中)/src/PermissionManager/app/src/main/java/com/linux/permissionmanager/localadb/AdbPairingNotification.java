package com.linux.permissionmanager.localadb;

import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.RemoteInput;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.utils.AppLaunchUtils;
import com.linux.permissionmanager.utils.DialogUtils;

public final class AdbPairingNotification {
    public static final String CHANNEL_ID = "adb_pairing";
    public static final int NOTIFICATION_ID = 0xADB1;
    public static final String REMOTE_INPUT_KEY = "adb_pairing_code";
    private static final String PERMISSION_POST_NOTIFICATIONS = "android.permission.POST_NOTIFICATIONS";
    private static final String REASON_CHANNEL_DISABLED = "配对通知渠道已被关闭";
    private static final int REQUEST_OPEN_APP = 100;
    private static final int REQUEST_REMOTE_INPUT = 101;
    private static final int REQUEST_STOP = 102;
    private AdbPairingNotification() {}

    public static void createChannel(Context context) {
        NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager == null) return;
        NotificationChannel channel = new NotificationChannel(CHANNEL_ID, "无线调试配对", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("显示配对进度，可直接在通知栏输入配对码");
        channel.setShowBadge(false);
        channel.setLockscreenVisibility(Notification.VISIBILITY_PRIVATE);
        manager.createNotificationChannel(channel);
    }

    public static boolean ensureNotificationsAvailable(Activity activity) {
        String reason = getUnavailableReason(activity);
        if (reason == null) return true;
        if (Build.VERSION.SDK_INT < 33) {
            DialogUtils.showMsgDlg(activity, "系统版本不支持", reason, null);
        } else {
            DialogUtils.showNeedPermissionDialog(activity, "通知权限");
            openNotificationSettings(activity);
        }
        return false;
    }

    public static String getUnavailableReason(Context context) {
        if (Build.VERSION.SDK_INT < 33) return "当前系统版本不支持，需要 Android 13 及以上";
        createChannel(context);
        if (context.checkSelfPermission(PERMISSION_POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return "尚未获得通知权限";
        NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager == null || !manager.areNotificationsEnabled()) return "应用通知已被关闭";
        NotificationChannel channel = manager.getNotificationChannel(CHANNEL_ID);
        if (channel == null || channel.getImportance() == NotificationManager.IMPORTANCE_NONE) return REASON_CHANNEL_DISABLED;
        return null;
    }

    public static void openNotificationSettings(Context context) {
        Intent intent;
        if (REASON_CHANNEL_DISABLED.equals(getUnavailableReason(context))) {
            intent = new Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS);
            intent.putExtra(Settings.EXTRA_APP_PACKAGE, context.getPackageName());
            intent.putExtra(Settings.EXTRA_CHANNEL_ID, CHANNEL_ID);
        } else {
            intent = new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS);
            intent.putExtra(Settings.EXTRA_APP_PACKAGE, context.getPackageName());
        }
        if (!(context instanceof Activity)) {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        }

        try {
            context.startActivity(intent);
        } catch (ActivityNotFoundException e) {
            try {
                context.startActivity(new Intent(Settings.ACTION_SETTINGS).addFlags(intent.getFlags()));
            } catch (ActivityNotFoundException ignored) {
            }
        }
    }

    private static Intent buildOpenAppIntent(Context context) {
        String launcherActivity = AppLaunchUtils.getLauncherActivityName(context);
        if (launcherActivity == null || launcherActivity.isEmpty()) return null;
        Intent intent = new Intent(Intent.ACTION_MAIN);
        intent.addCategory(Intent.CATEGORY_LAUNCHER);
        intent.setClassName(context.getPackageName(), launcherActivity);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        return intent;
    }

    public static Notification build(Context context, String title, String message, boolean canEnterPairingCode, boolean showReturnToApp, String detail, boolean busy) {
        Intent openIntent = buildOpenAppIntent(context);
        PendingIntent contentPendingIntent = openIntent == null ? null : PendingIntent.getActivity(context, REQUEST_OPEN_APP, openIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder builder = new Notification.Builder(context, CHANNEL_ID);

        String bigText = message == null ? "" : message;
        if (detail != null && !detail.trim().isEmpty()) {
            bigText += "\n" + detail.trim();
        }

        builder.setSmallIcon(R.drawable.ic_adb_notification)
                .setContentTitle(title)
                .setContentText(message)
                .setStyle(new Notification.BigTextStyle().bigText(bigText))
                .setCategory(Notification.CATEGORY_SERVICE)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setAutoCancel(false)
                .setShowWhen(false);
        if (busy) {
            builder.setProgress(0, 0, true);
        }
        if (contentPendingIntent != null) builder.setContentIntent(contentPendingIntent);

        if (showReturnToApp && contentPendingIntent != null) {
            builder.addAction(new Notification.Action.Builder(android.R.drawable.ic_menu_view, "回到APP", contentPendingIntent).build());
        }

        if (canEnterPairingCode) {
            // 接收器动态注册，没有组件名可指向，只能用 action + 包名定向到本应用。
            Intent replyIntent = new Intent(AdbPairingReceiver.ACTION_SUBMIT_PAIRING_CODE);
            replyIntent.setPackage(context.getPackageName());
            int replyPendingIntentFlags = PendingIntent.FLAG_UPDATE_CURRENT;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                replyPendingIntentFlags |= PendingIntent.FLAG_MUTABLE;
            }
            PendingIntent replyPendingIntent = PendingIntent.getBroadcast(context, REQUEST_REMOTE_INPUT, replyIntent, replyPendingIntentFlags);

            RemoteInput remoteInput = new RemoteInput.Builder(REMOTE_INPUT_KEY)
                    .setLabel("请输入 6 位配对码")
                    .setAllowFreeFormInput(true)
                    .build();

            Notification.Action.Builder pairingCodeActionBuilder = new Notification.Action.Builder(android.R.drawable.ic_menu_edit, "输入配对码", replyPendingIntent)
                            .addRemoteInput(remoteInput)
                            .setAllowGeneratedReplies(false);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pairingCodeActionBuilder.setSemanticAction(Notification.Action.SEMANTIC_ACTION_REPLY);
            }
            builder.addAction(pairingCodeActionBuilder.build());
        }
        Intent stopIntent = new Intent(AdbPairingReceiver.ACTION_STOP_SESSION);
        stopIntent.setPackage(context.getPackageName());
        PendingIntent stopPendingIntent = PendingIntent.getBroadcast(context, REQUEST_STOP, stopIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        builder.addAction(new Notification.Action.Builder(android.R.drawable.ic_menu_close_clear_cancel, "停止", stopPendingIntent).build());
        return builder.build();
    }
}
