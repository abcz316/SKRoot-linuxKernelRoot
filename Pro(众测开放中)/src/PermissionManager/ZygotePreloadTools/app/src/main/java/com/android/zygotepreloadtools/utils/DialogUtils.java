package com.android.zygotepreloadtools.utils;

import android.app.Activity;
import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;

import java.io.File;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class DialogUtils {
    public static void showCustomDialog(Context context, String title, String message, Drawable icon,
                                        String positiveButtonText, DialogInterface.OnClickListener positiveClickListener,
                                        String negativeButtonText, DialogInterface.OnClickListener negativeClickListener) {
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(title)
                .setMessage(message)
                .setCancelable(false);
        if (icon != null) builder.setIcon(icon);
        if (positiveButtonText != null && positiveClickListener != null) builder.setPositiveButton(positiveButtonText, positiveClickListener);
        if (negativeButtonText != null && negativeClickListener != null) builder.setNegativeButton(negativeButtonText, negativeClickListener);
        builder.show();
    }

    public static void showMsgDlg(Context context, String title, String msg, Drawable icon) {
        showCustomDialog(context, title, msg, icon, "确定", (dialog, which) -> dialog.dismiss(), null, null);
    }

    public static AlertDialog showSingleChoiceDialog(Context context, String title, String[] items, int checkedItem, DialogInterface.OnClickListener listener) {
        AlertDialog dialog = new AlertDialog.Builder(context)
                .setTitle(title != null ? title : "请选择一个选项")
                .setSingleChoiceItems(items, checkedItem, (d, which) -> {
                    d.dismiss();
                    if (listener != null) listener.onClick(d, which);
                })
                .setCancelable(false)
                .setNegativeButton("取消", (d, which) -> d.dismiss())
                .create();
        dialog.show();
        return dialog;
    }

    private static void saveLogsToFile(Activity activity, String logs) {
        File dir = activity.getExternalFilesDir(null);
        if (dir == null) {
            showMsgDlg(activity, "保存失败", "无法访问外部存储目录", null);
            return;
        }
        String name = "skroot_logs_" + new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(new Date()) + ".log";
        File outFile = new File(dir, name);
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            fos.write(logs.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            showMsgDlg(activity, "保存成功", "日志已保存到：\n" + outFile.getAbsolutePath(), null);
        } catch (Throwable t) {
            showMsgDlg(activity, "保存失败", "无法保存日志到：\n" + outFile.getAbsolutePath() + "\n\n错误信息：" + t.getMessage(), null);
        }
    }

    private static void showLogSaveSelectMenu(Activity activity, View view, String logs) {
        final String[] items = { "1.复制文本", "2.导出到文件" };
        showSingleChoiceDialog(activity, null, items, -1,
                (dialog, which) -> {
                    if (which == 0) {
                        ClipboardManager cm = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
                        cm.setPrimaryClip(ClipData.newPlainText("logs", logs));
                        Toast.makeText(activity, "日志已复制到剪贴板", Toast.LENGTH_SHORT).show();
                    } else if (which == 1) saveLogsToFile(activity, logs);
                }
        );
    }

    public static void dismissDialog(Dialog dialog) {
        if (dialog != null && dialog.isShowing()) dialog.dismiss();
    }

    /**
     * 通用日志对话框：既支持一次性显示完整日志，也支持执行过程中实时追加。
     */
    public static class LogDialog {
        private final Activity activity;
        private final Dialog dialog;
        private final TextView logView;
        private final ScrollView scrollView;
        private final Handler handler = new Handler(Looper.getMainLooper());
        private volatile boolean closed = false;

        public LogDialog(Activity activity, String title) { this(activity, title, "正在执行，请稍候…", true); }

        private LogDialog(Activity activity, String title, String initialText, boolean scrollToBottom) {
            this.activity = activity;
            dialog = new Dialog(activity);
            dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
            LinearLayout layout = new LinearLayout(activity);
            layout.setOrientation(LinearLayout.VERTICAL);
            layout.setPadding(50, 50, 50, 50);
            if (title != null && !title.isEmpty()) {
                TextView titleView = new TextView(activity);
                titleView.setText(title);
                titleView.setTextSize(16);
                titleView.setTextColor(Color.parseColor("#222222"));
                titleView.setPadding(0, 0, 0, 20);
                layout.addView(titleView);
            }
            logView = new TextView(activity);
            logView.setTextSize(13);
            logView.setTextIsSelectable(true);
            logView.setSingleLine(false);
            logView.setMaxLines(Integer.MAX_VALUE);
            logView.setLineSpacing(1.3f, 1.1f);
            logView.setTextColor(Color.parseColor("#333333"));
            logView.setText(initialText != null ? initialText : "");
            scrollView = new ScrollView(activity);
            scrollView.setVerticalScrollBarEnabled(true);
            scrollView.addView(logView);
            scrollView.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
            LinearLayout buttonBar = new LinearLayout(activity);
            buttonBar.setOrientation(LinearLayout.HORIZONTAL);
            buttonBar.setGravity(Gravity.END);
            LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            btnLp.setMargins(10, 30, 10, 0);
            Button saveButton = new Button(activity);
            saveButton.setText("保存");
            saveButton.setLayoutParams(btnLp);
            saveButton.setOnClickListener(v -> showLogSaveSelectMenu(activity, saveButton, logView.getText().toString()));
            Button closeButton = new Button(activity);
            closeButton.setText("关闭");
            closeButton.setLayoutParams(btnLp);
            closeButton.setOnClickListener(v -> dismiss());
            buttonBar.addView(saveButton);
            buttonBar.addView(closeButton);
            layout.addView(scrollView);
            layout.addView(buttonBar);
            dialog.setContentView(layout);
            dialog.setCancelable(false);
            dialog.setCanceledOnTouchOutside(false);
            Window window = dialog.getWindow();
            if (window != null) {
                window.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT);
                window.setGravity(Gravity.CENTER);
            }
            dialog.show();
            if (scrollToBottom) scrollToBottom();
        }

        public void setText(String text) {
            handler.post(() -> {
                if (closed) return;
                logView.setText(text != null ? text : "");
            });
        }

        public void appendLine(String line) {
            if (closed || line == null) return;
            handler.post(() -> {
                if (closed) return;
                if (logView.getText().length() > 0) logView.append("\n");
                logView.append(line);
                scrollToBottom();
            });
        }

        public void append(String text) { appendLine(text); }

        public boolean isClosed() { return closed; }

        public void dismiss() {
            closed = true;
            DialogUtils.dismissDialog(dialog);
        }

        private void scrollToBottom() {
            scrollView.post(() -> {
                int y = Math.max(0, logView.getHeight() - scrollView.getHeight());
                scrollView.scrollTo(0, y);
            });
        }
    }
}