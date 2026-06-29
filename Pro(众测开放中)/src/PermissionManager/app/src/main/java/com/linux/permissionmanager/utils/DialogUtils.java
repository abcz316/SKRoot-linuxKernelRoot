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
    public static void showCustomDialog(Context context, String title, String message,
                                        Drawable icon,
                                        String positiveButtonText, DialogInterface.OnClickListener positiveClickListener,
                                        String negativeButtonText, DialogInterface.OnClickListener negativeClickListener) {

        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(title)
                .setMessage(message)
                .setCancelable(false);

        if (icon != null) {
            builder.setIcon(icon);
        }

        if (positiveButtonText != null && positiveClickListener != null) {
            builder.setPositiveButton(positiveButtonText, positiveClickListener);
        }
        if (negativeButtonText != null && negativeClickListener != null) {
            builder.setNegativeButton(negativeButtonText, negativeClickListener);
        }
        builder.show();
    }

    public static void showNeedPermissionDialog(Context context) {
        DialogUtils.showCustomDialog(
                context, "权限申请", "请授予权限后重新操作", null, "确定",
                (dialog, which) -> dialog.dismiss(),
                null, null
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
        showCustomDialog(
                context,
                title,
                msg,
                icon,
                "确定", (dialog, which) -> dialog.dismiss(),
                null, null
        );
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
    public static void showInputDlg(Context context, String defaultText, String title, final String thirdButtonText,
                                    final Handler confirmCallback, final Handler thirdButtonCallback) {
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
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
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
                    if (thirdButtonCallback != null) {
                        thirdButtonCallback.sendMessage(new Message());
                    }
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
        final String[] items = {
                "1.复制文本",
                "2.导出到文件",
        };
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

    public static void showLogDialog(Activity activity, String logs, boolean scrollToBottoom) {
        // 创建全屏 Dialog
        Dialog dialog = new Dialog(activity);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);

        // 创建一个外部的线性布局（垂直方向）
        LinearLayout layout = new LinearLayout(activity);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(50, 50, 50, 50);

        // 创建 TextView 作为日志显示区域
        TextView textView = new TextView(activity);
        textView.setTextSize(14);
        textView.setText(logs);
        textView.setTextIsSelectable(true); // 允许选中复制
        textView.setVerticalScrollBarEnabled(true);
        textView.setSingleLine(false); // 允许多行显示
        textView.setMaxLines(Integer.MAX_VALUE); // 让其支持无限行
        textView.setLineSpacing(1.5f, 1.2f); // 增加行间距，增强可读性

        // ScrollView 使日志可以滚动
        ScrollView scrollView = new ScrollView(activity);
        scrollView.addView(textView);
        scrollView.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0, 1 // 设置权重，让日志区域填满大部分屏幕
        ));

        // 让 ScrollView 自动滚动到底部
        if(scrollToBottoom) {
            scrollView.getViewTreeObserver().addOnGlobalLayoutListener(() -> {
                scrollView.post(() -> scrollView.fullScroll(View.FOCUS_DOWN));
            });
        }

        // === 底部按钮区域：复制 + 关闭 ===
        LinearLayout buttonBar = new LinearLayout(activity);
        buttonBar.setOrientation(LinearLayout.HORIZONTAL);
        buttonBar.setGravity(Gravity.END);

        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        btnLp.setMargins(10, 30, 10, 0); // 按钮之间稍微留点间距

        // 【保存】按钮
        Button copyButton = new Button(activity);
        copyButton.setText("保存");
        copyButton.setLayoutParams(btnLp);
        copyButton.setOnClickListener(v -> showLogSaveSelectMenu(activity, copyButton, logs));

        // 【关闭】按钮
        Button closeButton = new Button(activity);
        closeButton.setText("关闭");
        closeButton.setLayoutParams(btnLp);
        closeButton.setOnClickListener(v -> dialog.dismiss());

        buttonBar.addView(copyButton);
        buttonBar.addView(closeButton);

        // 将 ScrollView 和按钮栏添加到主布局
        layout.addView(scrollView);
        layout.addView(buttonBar);

        // 设置 Dialog 的内容
        dialog.setContentView(layout);

        // 设置全屏属性
        Window window = dialog.getWindow();
        if (window != null) {
            window.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT);
            window.setGravity(Gravity.CENTER);
        }
        dialog.show();
    }

    public static Dialog showLoadingDialog(Context context, String message) {
        Dialog dialog = new Dialog(context);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setCancelable(false);
        dialog.setCanceledOnTouchOutside(false);

        // 最外层容器：透明背景下居中
        FrameLayout outer = new FrameLayout(context);
        outer.setPadding(dp(context, 24), dp(context, 24), dp(context, 24), dp(context, 24));

        // 白色圆角卡片
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setGravity(Gravity.CENTER_HORIZONTAL);
        card.setPadding(dp(context, 28), dp(context, 24), dp(context, 28), dp(context, 24));

        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.WHITE);
        bg.setCornerRadius(dp(context, 16));
        card.setBackground(bg);

        FrameLayout.LayoutParams cardLp = new FrameLayout.LayoutParams(
                dp(context, 260),
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        cardLp.gravity = Gravity.CENTER;
        card.setLayoutParams(cardLp);

        ProgressBar progressBar = new ProgressBar(context);
        LinearLayout.LayoutParams progressLp = new LinearLayout.LayoutParams(
                dp(context, 36),
                dp(context, 36)
        );
        progressLp.bottomMargin = dp(context, 16);
        progressBar.setLayoutParams(progressLp);

        TextView textView = new TextView(context);
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
        }

        dialog.show();
        return dialog;
    }

    private static int dp(Context context, int dp) {
        return (int) (dp * context.getResources().getDisplayMetrics().density + 0.5f);
    }

    public static void dismissDialog(Dialog dialog) {
        if (dialog != null && dialog.isShowing()) {
            dialog.dismiss();
        }
    }
}
