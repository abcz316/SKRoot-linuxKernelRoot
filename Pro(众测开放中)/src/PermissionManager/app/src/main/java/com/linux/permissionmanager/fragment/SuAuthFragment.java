package com.linux.permissionmanager.fragment;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.pm.PackageInfo;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.PopupMenu;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.adapter.SuAuthAdapter;
import com.linux.permissionmanager.bridge.NativeBridge;
import com.linux.permissionmanager.helper.SelectAppDlg;
import com.linux.permissionmanager.model.SelectAppItem;
import com.linux.permissionmanager.model.SuAuthItem;
import com.linux.permissionmanager.utils.DialogUtils;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;

public class SuAuthFragment extends Fragment {
    private Activity mActivity;
    private String mRootKey = "";

    private TextView mTextEmptyTips;
    private RecyclerView mSuAuthRecyclerView;

    private SuAuthAdapter mAdapter;

    public SuAuthFragment(Activity activity, String rootKey) {
        mActivity = activity;
        mRootKey = rootKey;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_su_auth, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        mTextEmptyTips = view.findViewById(R.id.empty_tips_tv);
        mSuAuthRecyclerView = view.findViewById(R.id.su_auth_recycler_view);
        setupSuAuthRecyclerView();
    }

    private void setupSuAuthRecyclerView() {
        String json = NativeBridge.getSuAuthList(mRootKey);
        List<SuAuthItem> skrModList = parseSuAuthList(json);
        mAdapter = new SuAuthAdapter(skrModList, new SuAuthAdapter.OnItemClickListener() {
            @Override
            public void onRemoveSuAuthBtnClick(View v, SuAuthItem suAuth) { onRemoveSuAuth(suAuth); }
        });
        mSuAuthRecyclerView.setAdapter(mAdapter);
        mSuAuthRecyclerView.setLayoutManager(new LinearLayoutManager(getContext()));
        mSuAuthRecyclerView.setVisibility(skrModList.size() == 0 ? View.GONE : View.VISIBLE);
        mTextEmptyTips.setVisibility(skrModList.size() == 0 ? View.VISIBLE : View.GONE);
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
            Drawable icon =  packageInfo.applicationInfo.loadIcon(mActivity.getPackageManager());
            return icon;
        }
        return null;
    }

    private List<SuAuthItem> parseSuAuthList(String jsonStr) {
        List<PackageInfo> packages = mActivity.getPackageManager().getInstalledPackages(0);
        List<SuAuthItem> list = new ArrayList<>();
        try {
            JSONArray jsonArray = new JSONArray(jsonStr);
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject jsonObject = jsonArray.getJSONObject(i);

                String appPackageName = URLDecoder.decode(jsonObject.getString("app_package_name"), "UTF-8");
                Drawable icon = findAppIcon(packages, appPackageName);
                String appName = findAppName(packages, appPackageName);
                SuAuthItem e = new SuAuthItem(icon, appName, appPackageName);
                list.add(e);
            }
        } catch (Exception e) {
            DialogUtils.showMsgDlg(mActivity, "发生错误", jsonStr, null);
            e.printStackTrace();
        }
        return list;
    }

    public void showSuAuthMainPopupMenu(View v) {
        PopupMenu popupMenu = new PopupMenu(mActivity, v);
        popupMenu.getMenuInflater().inflate(R.menu.popup_su_auth_main_menu, popupMenu.getMenu());
        popupMenu.setOnMenuItemClickListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.add_su_auth) onShowSelectAddSuAuthList();
            else if (itemId == R.id.clear_su_auth) onClearSuAuth();
            return true;
        });

        popupMenu.show();
    }

    private void onShowSelectAddSuAuthList() {
        Handler selectImplantAppCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                SelectAppItem app = (SelectAppItem) msg.obj;
                onAddSuAuth(app);
                super.handleMessage(msg);
            }
        };
        View view = SelectAppDlg.showSelectAppDlg(mActivity, mRootKey, selectImplantAppCallback);
        CheckBox show_system_app_ckbox = view.findViewById(R.id.show_system_app_ckbox);
        CheckBox show_thirty_app_ckbox = view.findViewById(R.id.show_thirty_app_ckbox);
        show_system_app_ckbox.setChecked(false);
        show_thirty_app_ckbox.setChecked(true);
    }

    private void onAddSuAuth(SelectAppItem app) {
        String appPackageName = app.getPackageName();
        String tip = NativeBridge.addSuAuth(mRootKey, appPackageName);
        DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
        setupSuAuthRecyclerView();
    }

    private void onRemoveSuAuth(SuAuthItem suAuth) {
        String appName = suAuth.getAppName();
        String appPackageName = suAuth.getAppPackageName();
        String showName = appName != null && !appName.isEmpty() ? appName : appPackageName;
        DialogUtils.showCustomDialog(mActivity, "确认", "确定要移除 " + showName +" 吗？", null,"确定",
                (dialog, which) -> {
                    dialog.dismiss();
                    String tip = NativeBridge.removeSuAuth(mRootKey, appPackageName);
                    DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
                    setupSuAuthRecyclerView();
                },
                "取消", (dialog, which) -> {
                    dialog.dismiss();
                }
        );
    }

    private void onClearSuAuth() {
        DialogUtils.showCustomDialog(mActivity, "确认", "确定要清空 SU 授权列表吗？", null, "确定",
                (dialog, which) -> {
                    dialog.dismiss();
                    String tip = NativeBridge.clearSuAuthList(mRootKey);
                    DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
                    setupSuAuthRecyclerView();
                },
                "取消", (dialog, which) -> {
                    dialog.dismiss();
                }
        );
    }
}
