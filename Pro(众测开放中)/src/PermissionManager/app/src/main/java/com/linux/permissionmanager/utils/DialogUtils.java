package com.linux.permissionmanager.utils;

import android.app.Activity;
import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.fragment.SettingsFragment;

import java.io.File;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
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

    public static void showNeedPermissionDialog(Context context) {
        DialogUtils.showCustomDialog(context, "权限申请", "请授予权限后重新操作", null, "确定",
                (dialog, which) -> dialog.dismiss(), null, null
        );
    }

    /**
     * 显示带有消息的对话框。
     *
     * @param context 上下文
     * @param title   对话框标题
     * @param msg     对话框内容
     * @param icon    对话框图标（可为 null）
     */
    public static void showMsgDlg(Context context, String title, String msg, Drawable icon) {
        showCustomDialog(context, title, msg, icon, "确定", (dialog, which) -> dialog.dismiss(), null, null);
    }

    /**
     * 显示带有三个按钮的输入对话框。
     *
     * @param context           上下文
     * @param defaultText       默认文本
     * @param title             对话框标题
     * @param thirdButtonText   第三个按钮的文本
     * @param confirmCallback   点击确定按钮时的回调
     * @param thirdButtonCallback 第三个按钮的回调
     */
    public static void showInputDlg(Context context, String defaultText, String title, final String thirdButtonText, final Handler confirmCallback, final Handler thirdButtonCallback) {
        final EditText inputTxt = new EditText(context);
        inputTxt.setText(defaultText);
        inputTxt.setFocusable(true);
        inputTxt.setSelection(defaultText.length(), 0);

        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(title)
                .setIcon(android.R.drawable.ic_dialog_info)
                .setView(inputTxt)
                .setNegativeButton("取消", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) { dialog.dismiss(); }
                })
                .setPositiveButton("确定", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        String text = inputTxt.getText().toString();
                        Message msg = new Message();
                        msg.obj = text;
                        confirmCallback.sendMessage(msg);
                    }
                });

        // 添加第三个按钮
        if (thirdButtonText != null && !thirdButtonText.isEmpty()) {
            builder.setNeutralButton(thirdButtonText, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    // 自定义回调
                    if (thirdButtonCallback != null) thirdButtonCallback.sendMessage(new Message());
                }
            });
        }
        AlertDialog dialog = builder.create();
        dialog.show();
    }

    public static AlertDialog showSingleChoiceDialog(Context context, String title, String[] items, int checkedItem, DialogInterface.OnClickListener listener) {
        AlertDialog dialog = new AlertDialog.Builder(context)
                .setTitle(title != null ? title : "请选择一个选项")
                .setSingleChoiceItems(items, checkedItem, (d, which) -> {
                    d.dismiss();
                    if (listener != null) listener.onClick(d, which);
                })
                .setNegativeButton("取消", (d, which) -> d.dismiss())
                .create();
        dialog.show();
        return dialog;
    }

    private static void saveLogsToSdcard(Activity activity, String logs) {
        File outFile = FileUtils.makeSdcardLogFile("skroot_logs_", ".log");
        FileUtils.writeTextAsync(activity, outFile, logs, false, (ok, file, errMsg) -> {
            if (ok) DialogUtils.showMsgDlg(activity,"保存成功", "日志已保存到：\n" + file.getAbsolutePath(),null);
            else DialogUtils.showMsgDlg(activity, "保存失败", "无法保存日志到：\n" + file.getAbsolutePath() + "\n\n错误信息：" + (errMsg == null ? "unknown" : errMsg), null);
        });
    }

    private static void showLogSaveSelectMenu(Activity activity, View anchor, String logs) {
        if(!GetSdcardPermissionsHelper.getPermissions(activity, activity, activity.getPackageName())) {
            DialogUtils.showNeedPermissionDialog(activity);
            return;
        }
        final String[] items = { "1.复制文本", "2.导出到文件", };
        DialogUtils.showSingleChoiceDialog(activity, null, items, -1,
                (dialog, which) -> {
                    if (which == 0) {
                        ClipboardManager cm = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
                        cm.setPrimaryClip(ClipData.newPlainText("logs", logs));
                        Toast.makeText(activity, "日志已复制到剪贴板", Toast.LENGTH_SHORT).show();
                    } else if (which == 1) saveLogsToSdcard(activity, logs);
                }
        );
    }

    public static void showLogDialog(Activity activity, String logs, boolean scrollToBottom) {
        new LogDialog(activity, null, logs, scrollToBottom);
    }

    private static int dp(Context context, int dp) {
        return (int) (dp * context.getResources().getDisplayMetrics().density + 0.5f);
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
