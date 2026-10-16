package com.linux.permissionmanager.helper;

import android.app.Activity;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.text.InputType;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.core.content.ContextCompat;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.model.GenerateFakeAppConfig;
import com.linux.permissionmanager.utils.AppCertUtils;
import com.linux.permissionmanager.utils.AppLaunchUtils;
import com.linux.permissionmanager.utils.FileUtils;

public class GenerateFakeAppDlg {

    public interface Callback { void onInstallApk(GenerateFakeAppConfig config, Runnable dismissConfigDialog); }

    private static final int TEXT_PRIMARY = 0xFF222222;
    private static final int TEXT_SECONDARY = 0xFF757575;

    private final Activity mActivity;
    private AlertDialog mCurrentDialog;

    public GenerateFakeAppDlg(Activity activity) { mActivity = activity; }

    private int dp(float value) { return Math.round(value * mActivity.getResources().getDisplayMetrics().density); }
    private int withAlpha(int color, int alpha) { return (color & 0x00FFFFFF) | ((alpha & 0xFF) << 24); }
    private int primaryColor() { return ContextCompat.getColor(mActivity, R.color.purple_500); }

    private GradientDrawable roundedBg(float radiusDp, int fillColor, int strokeColor, float strokeDp) {
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(radiusDp));
        bg.setColor(fillColor);
        if (strokeDp > 0) bg.setStroke(dp(strokeDp), strokeColor);
        return bg;
    }

    private TextView makeFieldLabel(String text, boolean first) {
        TextView label = new TextView(mActivity);
        label.setText(text); label.setTextColor(TEXT_SECONDARY);
        label.setTextSize(13);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(dp(2), first ? 0 : dp(8), 0, dp(4));
        label.setLayoutParams(lp);
        return label;
    }

    private EditText makeFieldInput(String text) {
        EditText input = new EditText(mActivity);
        input.setText(text);
        input.setSingleLine(true);
        input.setTextSize(14);
        input.setTextColor(TEXT_PRIMARY);
        int normalStroke = 0xFFC9C9C9, focusStroke = primaryColor();
        input.setBackground(roundedBg(8, Color.WHITE, normalStroke, 1));
        input.setPadding(dp(10), dp(8), dp(10), dp(8));
        if (text != null) input.setSelection(text.length());
        input.setOnFocusChangeListener((v, hasFocus) -> input.setBackground(roundedBg(8, Color.WHITE, hasFocus ? focusStroke : normalStroke, hasFocus ? 1.5f : 1)));
        return input;
    }

    private TextView makeOutlineButton(String text, View.OnClickListener listener) {
        int color = primaryColor();
        TextView btn = new TextView(mActivity);
        btn.setText(text); btn.setTextSize(14);
        btn.setTextColor(color); btn.setGravity(Gravity.CENTER);
        btn.setSingleLine(true);
        btn.setPadding(dp(12), dp(5), dp(12), dp(5));
        btn.setMinHeight(dp(34)); btn.setClickable(true);
        btn.setFocusable(true);
        btn.setBackground(roundedBg(7, Color.TRANSPARENT, withAlpha(color, 0x66), 1));
        btn.setOnClickListener(listener);
        return btn;
    }

    /** 先选择应用，选择成功后才显示配置弹窗。 */
    public void showGenerateFakeAppDlg(Callback callback) {
        if (callback == null || mActivity.isFinishing()) return;
        if (mCurrentDialog != null && mCurrentDialog.isShowing()) return;

        SelectAppDlg.showSelectAppDlg(mActivity, null, item -> {
            if (item == null || mActivity.isFinishing()) return;
            GenerateFakeAppConfig config = new GenerateFakeAppConfig();
            config.pkgName = item.getPackageName();
            if (TextUtils.isEmpty(config.pkgName)) return;
            config.appName = item.getShowName(mActivity);
            config.launchActivity = AppLaunchUtils.getLauncherActivityName(mActivity, config.pkgName);
            config.iconDrawable = item.getDrawable(mActivity);
            try {
                PackageInfo info = mActivity.getPackageManager().getPackageInfo(config.pkgName, 0);
                config.versionName = info.versionName == null ? "" : info.versionName;
                config.versionCode = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P ? info.getLongVersionCode() : (info.versionCode & 0xFFFFFFFFL);
            } catch (PackageManager.NameNotFoundException e) {
                Toast.makeText(mActivity, "获取应用版本信息失败: " + config.pkgName, Toast.LENGTH_SHORT).show();
                return;
            }

            config.certInfo = createDefaultCertInfo();
            try {
                AppCertUtils.CertInfo cert = AppCertUtils.getCertInfo(mActivity, config.pkgName);
                if (cert != null) config.certInfo = copyCertInfo(cert);
            } catch (Exception e) {
                Toast.makeText(mActivity, "获取签名信息失败: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }

            showConfigDialog(config, callback);
        });
    }

    private static AppCertUtils.CertInfo createDefaultCertInfo() {
        AppCertUtils.CertInfo cert = new AppCertUtils.CertInfo();
        cert.certCN = "Android";
        cert.certO = "Google Inc.";
        cert.certOU = "Android";
        cert.certL = "Mountain View";
        cert.certST = "California";
        cert.certC = "US";
        return cert;
    }

    private static AppCertUtils.CertInfo copyCertInfo(AppCertUtils.CertInfo source) {
        AppCertUtils.CertInfo cert = new AppCertUtils.CertInfo();
        cert.certCN = source.certCN;
        cert.certO = source.certO;
        cert.certOU = source.certOU;
        cert.certL = source.certL;
        cert.certST = source.certST;
        cert.certC = source.certC;
        return cert;
    }

    private void showConfigDialog(GenerateFakeAppConfig config, Callback callback) {
        EditText pkgInput = makeFieldInput(config.pkgName);
        EditText appNameInput = makeFieldInput(config.appName == null ? "" : config.appName);
        EditText launchActivityInput = makeFieldInput(TextUtils.isEmpty(config.launchActivity) ? "" : config.launchActivity);
        EditText versionNameInput = makeFieldInput(config.versionName);
        EditText versionCodeInput = makeFieldInput(Long.toString(config.versionCode));
        versionCodeInput.setInputType(InputType.TYPE_CLASS_NUMBER);

        LinearLayout layout = new LinearLayout(mActivity);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(dp(16), dp(16), dp(16), dp(8));

        // 图标和 APP 名称并排。
        LinearLayout appRow = new LinearLayout(mActivity);
        appRow.setOrientation(LinearLayout.HORIZONTAL);
        appRow.setGravity(Gravity.CENTER_VERTICAL);
        ImageView iconPreview = new ImageView(mActivity);
        if (config.iconDrawable != null) iconPreview.setImageDrawable(config.iconDrawable);
        else iconPreview.setImageResource(android.R.drawable.sym_def_app_icon);
        iconPreview.setScaleType(ImageView.ScaleType.FIT_CENTER);
        iconPreview.setContentDescription("应用图标预览");
        appRow.addView(iconPreview, new LinearLayout.LayoutParams(dp(56), dp(56)));

        LinearLayout nameColumn = new LinearLayout(mActivity);
        nameColumn.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams nameLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        nameLp.leftMargin = dp(12);
        appRow.addView(nameColumn, nameLp);
        nameColumn.addView(makeFieldLabel("APP 名称", true));
        nameColumn.addView(appNameInput, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        layout.addView(appRow);

        layout.addView(makeFieldLabel("包名", false));
        layout.addView(pkgInput);

        layout.addView(makeFieldLabel("启动 Activity", false));
        layout.addView(launchActivityInput);

        LinearLayout versionRow = new LinearLayout(mActivity);
        versionRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout versionNameColumn = new LinearLayout(mActivity);
        LinearLayout versionCodeColumn = new LinearLayout(mActivity);
        versionNameColumn.setOrientation(LinearLayout.VERTICAL);
        versionCodeColumn.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams versionNameLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        LinearLayout.LayoutParams versionCodeLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        versionCodeLp.leftMargin = dp(12);
        versionNameColumn.addView(makeFieldLabel("版本名称", false));
        versionNameColumn.addView(versionNameInput);
        versionCodeColumn.addView(makeFieldLabel("版本代码", false));
        versionCodeColumn.addView(versionCodeInput);
        versionRow.addView(versionNameColumn, versionNameLp);
        versionRow.addView(versionCodeColumn, versionCodeLp);
        layout.addView(versionRow);

        LinearLayout checkRow = new LinearLayout(mActivity);
        checkRow.setOrientation(LinearLayout.HORIZONTAL);
        checkRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams checkLp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        checkLp.topMargin = dp(14);

        CheckBox fakeSizeCheck = new CheckBox(mActivity);
        fakeSizeCheck.setText("伪装体积");
        fakeSizeCheck.setTextSize(13);
        fakeSizeCheck.setTextColor(TEXT_SECONDARY);
        fakeSizeCheck.setButtonTintList(ColorStateList.valueOf(primaryColor()));
        fakeSizeCheck.setPadding(0, 0, 0, 0);
        fakeSizeCheck.setChecked(true);
        checkRow.addView(fakeSizeCheck);

        CheckBox removeIconCheck = new CheckBox(mActivity);
        removeIconCheck.setText("去除图标");
        removeIconCheck.setTextSize(13);
        removeIconCheck.setTextColor(TEXT_SECONDARY);
        removeIconCheck.setButtonTintList(ColorStateList.valueOf(primaryColor()));
        removeIconCheck.setPadding(0, 0, 0, 0);
        removeIconCheck.setOnCheckedChangeListener((v, checked) -> iconPreview.setAlpha(checked ? 0.35f : 1f));
        LinearLayout.LayoutParams removeIconLp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        removeIconLp.leftMargin = dp(12);
        checkRow.addView(removeIconCheck, removeIconLp);
        layout.addView(checkRow, checkLp);

        LinearLayout certRow = new LinearLayout(mActivity);
        LinearLayout.LayoutParams certLp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        certLp.topMargin = dp(8);
        certRow.addView(makeOutlineButton("设置签名主体", v -> showCertConfigDlg(config.certInfo)));
        layout.addView(certRow, certLp);

        ScrollView scrollView = new ScrollView(mActivity);
        scrollView.setFillViewport(false); scrollView.addView(layout);
        AlertDialog dialog = new AlertDialog.Builder(mActivity)
            .setTitle("新应用配置")
            .setView(scrollView)
            .setCancelable(false)
            .setNegativeButton("取消", (d, which) -> d.dismiss())
            .setPositiveButton("开始安装", null).create();

        dialog.setOnShowListener(d -> {
            View customPanel = dialog.findViewById(android.R.id.custom);
            if (customPanel != null) customPanel.setPadding(customPanel.getPaddingLeft(), customPanel.getPaddingTop(), customPanel.getPaddingRight(), 0);
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String versionCodeText = versionCodeInput.getText().toString().trim();
            long editedVersionCode;
            try {
                editedVersionCode = Long.parseLong(versionCodeText);
                if (editedVersionCode < 0) throw new NumberFormatException("versionCode must be >= 0");
            } catch (NumberFormatException e) {
                versionCodeInput.setError("请输入有效的非负整数版本代码");
                versionCodeInput.requestFocus();
                return;
            }
            GenerateFakeAppConfig result = new GenerateFakeAppConfig();
            result.pkgName = pkgInput.getText().toString();
            result.appName = appNameInput.getText().toString();
            result.originalAppName = config.appName;
            result.launchActivity = launchActivityInput.getText().toString();
            result.versionName = versionNameInput.getText().toString();
            result.versionCode = editedVersionCode;
            result.removeIcon = removeIconCheck.isChecked();
            result.fakeSize = fakeSizeCheck.isChecked() ? FileUtils.getAppApkSize(mActivity, result.pkgName) : null;
            result.iconDrawable = iconPreview.getDrawable();
            result.certInfo = copyCertInfo(config.certInfo);
            callback.onInstallApk(result, dialog::dismiss);
        });
    });

        mCurrentDialog = dialog;
        dialog.setOnDismissListener(d -> {
            if (mCurrentDialog == dialog) {
                mCurrentDialog = null;
            }
        });
        dialog.show();
    }

    private void showCertConfigDlg(AppCertUtils.CertInfo cert) {
        LinearLayout layout = new LinearLayout(mActivity);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(dp(16), dp(16), dp(16), dp(4));

        layout.addView(makeFieldLabel("Common Name (CN)", true));
        EditText cnInput = makeFieldInput(cert.certCN); layout.addView(cnInput);
        layout.addView(makeFieldLabel("Organization (O)", false));
        EditText oInput = makeFieldInput(cert.certO); layout.addView(oInput);
        layout.addView(makeFieldLabel("Organizational Unit (OU)", false));
        EditText ouInput = makeFieldInput(cert.certOU); layout.addView(ouInput);
        layout.addView(makeFieldLabel("Locality (L)", false));
        EditText lInput = makeFieldInput(cert.certL); layout.addView(lInput);
        layout.addView(makeFieldLabel("State / Province (ST)", false));
        EditText stInput = makeFieldInput(cert.certST); layout.addView(stInput);
        layout.addView(makeFieldLabel("Country (C)", false));
        EditText cInput = makeFieldInput(cert.certC); layout.addView(cInput);

        ScrollView scrollView = new ScrollView(mActivity);
        scrollView.addView(layout);
        AlertDialog dialog = new AlertDialog.Builder(mActivity)
            .setTitle("设置签名主体")
            .setView(scrollView)
            .setCancelable(false)
            .setNegativeButton("取消", (d, which) -> d.dismiss())
            .setPositiveButton("确定", (d, which) -> {
                cert.certCN = cnInput.getText().toString();
                cert.certO = oInput.getText().toString();
                cert.certOU = ouInput.getText().toString();
                cert.certL = lInput.getText().toString();
                cert.certST = stInput.getText().toString();
                cert.certC = cInput.getText().toString();
            }).create();
        dialog.show();
    }
}