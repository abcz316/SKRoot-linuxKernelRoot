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
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
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

    public static void showNeedPermissionDialog(Context context, String permissionName) {
        String msg = TextUtils.isEmpty(permissionName) ? "请授予「所需权限」后重新操作" : "请授予「" + permissionName + "」后重新操作";
        DialogUtils.showMsgDlg(context, "权限申请", msg, null);
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
                .setCancelable(false)
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
        return showSingleChoiceDialog(context, title, items, checkedItem, null, listener);
    }

    public static AlertDialog showSingleChoiceDialog(Context context, String title, String[] items, int checkedItem, CharSequence footNote, DialogInterface.OnClickListener listener) {
        AlertDialog.Builder builder = new AlertDialog.Builder(context)
                .setTitle(title != null ? title : "请选择一个选项")
                .setSingleChoiceItems(items, checkedItem, (d, which) -> {
                    d.dismiss();
                    if (listener != null) new Handler(Looper.getMainLooper()).post(() -> listener.onClick(d, which));
                })
                .setCancelable(false)
                .setNegativeButton("取消", (d, which) -> d.dismiss());
        // AlertDialog 的 customPanel 位于列表之后、按钮栏之前，借它放置列表下方的脚注
        if (!TextUtils.isEmpty(footNote)) builder.setView(createFootNoteView(context, footNote));
        AlertDialog dialog = builder.create();
        dialog.show();
        return dialog;
    }

    private static View createFootNoteView(Context context, CharSequence text) {
        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.VERTICAL);
        View divider = new View(context);
        divider.setBackgroundColor(0xFFEEEEEE);
        LinearLayout.LayoutParams dividerLp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, Math.max(1, dp(context, 1)));
        dividerLp.setMargins(dp(context, 24), 0, dp(context, 24), 0);
        container.addView(divider, dividerLp);
        TextView tv = new TextView(context);
        tv.setText(text);
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        tv.setTextColor(0xFF666666);
        tv.setLineSpacing(0f, 1.25f);
        tv.setPadding(dp(context, 24), dp(context, 10), dp(context, 24), dp(context, 12));
        container.addView(tv);
        return container;
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
            DialogUtils.showNeedPermissionDialog(activity, "文件存储权限");
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

    public static Dialog showLoadingDialog(Activity activity, String message) {
        Dialog dialog = new Dialog(activity);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setCancelable(false);
        dialog.setCanceledOnTouchOutside(false);

        // 最外层容器：透明背景下居中
        FrameLayout outer = new FrameLayout(activity);
        outer.setPadding(dp(activity, 24), dp(activity, 24), dp(activity, 24), dp(activity, 24));

        // 白色圆角卡片
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setGravity(Gravity.CENTER_HORIZONTAL);
        card.setPadding(dp(activity, 28), dp(activity, 24), dp(activity, 28), dp(activity, 24));

        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.WHITE);
        bg.setCornerRadius(dp(activity, 16));
        card.setBackground(bg);

        FrameLayout.LayoutParams cardLp = new FrameLayout.LayoutParams(
                dp(activity, 260),
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        cardLp.gravity = Gravity.CENTER;
        card.setLayoutParams(cardLp);

        ProgressBar progressBar = new ProgressBar(activity);
        LinearLayout.LayoutParams progressLp = new LinearLayout.LayoutParams(
                dp(activity, 36),
                dp(activity, 36)
        );
        progressLp.bottomMargin = dp(activity, 16);
        progressBar.setLayoutParams(progressLp);

        TextView textView = new TextView(activity);
        textView.setText(message);
        textView.setTextSize(15);
        textView.setTextColor(Color.parseColor("#222222"));
        textView.setGravity(Gravity.CENTER);
        textView.setLineSpacing(0f, 1.2f);

        LinearLayout.LayoutParams textLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        textView.setLayoutParams(textLp);

        card.addView(progressBar);
        card.addView(textView);
        outer.addView(card);

        dialog.setContentView(outer);

        Window window = dialog.getWindow();
        if (window != null) {
            window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            window.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            window.setGravity(Gravity.CENTER);
            // 加载期间保持屏幕常亮，避免中途锁屏。
            window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        }

        // 弹出期间锁定屏幕方向，关闭后恢复。
        final int previousOrientation = ScreenInfoUtils.lockOrientation(activity);
        dialog.setOnDismissListener(d -> ScreenInfoUtils.restoreOrientation(activity, previousOrientation));

        dialog.show();
        return dialog;
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
        private final int previousOrientation;
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
                // 执行脚本期间保持屏幕常亮，避免中途锁屏导致看不到进度/结果。
                window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            }
            // 弹出期间锁定屏幕方向，关闭后恢复。
            previousOrientation = ScreenInfoUtils.lockOrientation(activity);
            dialog.setOnDismissListener(d -> ScreenInfoUtils.restoreOrientation(activity, previousOrientation));
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