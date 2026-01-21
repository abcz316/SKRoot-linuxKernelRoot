package com.linux.permissionmanager.utils;

import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Message;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;

import java.util.List;

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

    public static void showLogDialog(Context context, String logs) {
        // 创建全屏 Dialog
        Dialog dialog = new Dialog(context);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);

        // 创建一个外部的线性布局（垂直方向）
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(50, 50, 50, 50);

        // 创建 TextView 作为日志显示区域
        TextView textView = new TextView(context);
        textView.setTextSize(14);
        textView.setText(logs);
        textView.setTextIsSelectable(true); // 允许选中复制
        textView.setVerticalScrollBarEnabled(true);
        textView.setSingleLine(false); // 允许多行显示
        textView.setMaxLines(Integer.MAX_VALUE); // 让其支持无限行
        textView.setLineSpacing(1.5f, 1.2f); // 增加行间距，增强可读性

        // ScrollView 使日志可以滚动
        ScrollView scrollView = new ScrollView(context);
        scrollView.addView(textView);
        scrollView.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0, 1 // 设置权重，让日志区域填满大部分屏幕
        ));

        // 让 ScrollView 自动滚动到底部
        scrollView.getViewTreeObserver().addOnGlobalLayoutListener(() -> {
            scrollView.post(() -> scrollView.fullScroll(View.FOCUS_DOWN));
        });

        // === 底部按钮区域：复制 + 关闭 ===
        LinearLayout buttonBar = new LinearLayout(context);
        buttonBar.setOrientation(LinearLayout.HORIZONTAL);
        buttonBar.setGravity(Gravity.END);

        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
        );
        btnLp.setMargins(10, 30, 10, 0); // 按钮之间稍微留点间距

        // 【复制】按钮
        Button copyButton = new Button(context);
        copyButton.setText("复制");
        copyButton.setLayoutParams(btnLp);
        copyButton.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("logs", logs));
                Toast.makeText(context, "日志已复制到剪贴板", Toast.LENGTH_SHORT).show();
            }
        });

        // 【关闭】按钮
        Button closeButton = new Button(context);
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

}
