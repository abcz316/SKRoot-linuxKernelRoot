package com.linux.permissionmanager.page;

import android.app.Activity;
import android.content.pm.PackageInfo;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.adapter.SuProbeAdapter;
import com.linux.permissionmanager.bridge.NativeBridge;
import com.linux.permissionmanager.model.SuProbeItem;
import com.linux.permissionmanager.utils.DialogUtils;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SuProbeRecordsPage {
    private Activity mActivity;
    private String mRootKey = "";

    private RecyclerView mSuProbeRecyclerView;
    private TextView mTextEmptyTips;
    private View mLoadingLayout;

    private SuProbeAdapter mAdapter;

    public SuProbeRecordsPage(Activity activity, String rootKey) {
        mActivity = activity;
        mRootKey = rootKey;
    }

    public void bindPage(@NonNull View view) {
        mSuProbeRecyclerView = view.findViewById(R.id.su_probe_recycler_view);
        mTextEmptyTips = view.findViewById(R.id.probe_empty_tips_tv);
        mLoadingLayout = view.findViewById(R.id.probe_loading_layout);
        setupSuProbeRecyclerView();
    }

    public void refreshPage() { setupSuProbeRecyclerView(); }

    private void setupSuProbeRecyclerView() {
        showLoading(true);
        new Thread(() -> {
            String json = NativeBridge.getSuProbeRecords(mRootKey);
            List<SuProbeItem> suProbeList = parseSuProbeList(json);
            mActivity.runOnUiThread(() -> {
                showLoading(false);
                mAdapter = new SuProbeAdapter(suProbeList);
                mSuProbeRecyclerView.setAdapter(mAdapter);
                mSuProbeRecyclerView.setLayoutManager(new LinearLayoutManager(mActivity));
                mSuProbeRecyclerView.setVisibility(suProbeList.size() == 0 ? View.GONE : View.VISIBLE);
                mTextEmptyTips.setVisibility(suProbeList.size() == 0 ? View.VISIBLE : View.GONE);
            });
        }).start();
    }

    private void showLoading(boolean show) {
        if (mLoadingLayout != null) {
            mLoadingLayout.setVisibility(show ? View.VISIBLE : View.GONE);
        }
    }

    private String findAppName(List<PackageInfo> packages, String appPackageName) {
        for (int i = 0; i < packages.size(); i++) {
            PackageInfo packageInfo = packages.get(i);
            String packageName = packageInfo.applicationInfo.packageName;
            if(!packageName.equals(appPackageName)) continue;
            String showName = packageInfo.applicationInfo.loadLabel(mActivity.getPackageManager()).toString();
            return showName;
        }
        return "";
    }

    private Drawable findAppIcon(List<PackageInfo> packages, String appPackageName) {
        for (int i = 0; i < packages.size(); i++) {
            PackageInfo packageInfo = packages.get(i);
            String packageName = packageInfo.applicationInfo.packageName;
            if(!packageName.equals(appPackageName)) continue;
            Drawable icon = packageInfo.applicationInfo.loadIcon(mActivity.getPackageManager());
            return icon;
        }
        return mActivity.getDrawable(android.R.drawable.sym_def_app_icon);
    }

    private Set<String> loadSuAuthPkgsNames() {
        Set<String> packages = new HashSet<>();
        try {
            String json = NativeBridge.getSuAuthList(mRootKey);
            JSONArray jsonArray = new JSONArray(json);
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject jsonObject = jsonArray.getJSONObject(i);
                String pkg = URLDecoder.decode(jsonObject.getString("app_package_name"), "UTF-8");
                packages.add(pkg);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return packages;
    }

    private List<SuProbeItem> parseSuProbeList(String jsonStr) {
        List<PackageInfo> packages = mActivity.getPackageManager().getInstalledPackages(0);
        Set<String> suAuthPkgs = loadSuAuthPkgsNames();
        List<SuProbeItem> list = new ArrayList<>();
        try {
            JSONArray jsonArray = new JSONArray(jsonStr);
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject jsonObject = jsonArray.getJSONObject(i);
                String appPackageName = URLDecoder.decode(jsonObject.getString("app_package_name"), "UTF-8");
                long appId = jsonObject.optLong("app_id", 0);
                int probeCount = jsonObject.getInt("probe_count");
                long lastProbeTimeS = jsonObject.getLong("last_probe_time_s");
                Drawable icon = findAppIcon(packages, appPackageName);
                String appName = findAppName(packages, appPackageName);
                if (appName.isEmpty()) appName = appPackageName;
                boolean isAuthorized = suAuthPkgs.contains(appPackageName);
                SuProbeItem e = new SuProbeItem(icon, appName, appPackageName, appId, probeCount, lastProbeTimeS, isAuthorized);
                list.add(e);
            }
        } catch (Exception e) {
            mActivity.runOnUiThread(() -> DialogUtils.showMsgDlg(mActivity, "发生错误", jsonStr, null));
            e.printStackTrace();
        }
        return list;
    }
}
