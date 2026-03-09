package com.linux.permissionmanager.helper;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.graphics.drawable.ColorDrawable;
import android.os.Handler;
import android.os.Message;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.adapter.SelectAppAdapter;
import com.linux.permissionmanager.bridge.NativeBridge;
import com.linux.permissionmanager.model.SelectAppItem;
import com.linux.permissionmanager.utils.ScreenInfoUtils;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SelectAppDlg {
    public static View showSelectAppDlg(Activity activity, String rootKey, Handler selectAppCallback) {
        final PopupWindow popupWindow = new PopupWindow(activity);
        View view = View.inflate(activity, R.layout.select_app_wnd, null);
        popupWindow.setContentView(view);
        popupWindow.setHeight(ViewGroup.LayoutParams.MATCH_PARENT);
        popupWindow.setWidth(ViewGroup.LayoutParams.MATCH_PARENT);
        popupWindow.setBackgroundDrawable(new ColorDrawable(0x9B000000));
        popupWindow.setOutsideTouchable(true);
        popupWindow.setFocusable(true);
        popupWindow.setTouchable(true);
        //全屏
        View parent = View.inflate(activity, R.layout.activity_main, null);
        popupWindow.showAtLocation(parent, Gravity.NO_GRAVITY, 0, 0);
        popupWindow.setOnDismissListener(new PopupWindow.OnDismissListener() {
            @Override
            public void onDismiss() {}
        });
        final int screenWidth = ScreenInfoUtils.getRealWidth(activity);
        final int screenHeight = ScreenInfoUtils.getRealHeight(activity);

        final double centerWidth = ((double) screenWidth) * 0.80;
        final double centerHeight = ((double) screenHeight) * 0.90;

        LinearLayout center_layout = (LinearLayout) view.findViewById(R.id.center_layout);
        ViewGroup.LayoutParams lp = center_layout.getLayoutParams();
        lp.width = (int) centerWidth;
        lp.height = (int) centerHeight;
        center_layout.setLayoutParams(lp);

        // 外层容器：点到阴影就关闭弹窗
        View outside = view.findViewById(R.id.popup_outside_container);
        outside.setOnClickListener(v -> popupWindow.dismiss());
        // 中间内容区域：消费点击，不往外传（防止点内容也被当成点阴影）
        center_layout.setOnClickListener(v -> {
            // 什么都不做，只是阻止事件传到 outside
        });

        List<SelectAppItem> appList = new ArrayList<>();
        List<PackageInfo> packages = activity.getPackageManager().getInstalledPackages(0);

        for (int i = 0; i < packages.size(); i++) {
            PackageInfo packageInfo = packages.get(i);
            String packageName = packageInfo.applicationInfo.packageName;
            if(packageName.equals(activity.getPackageName())) continue;
            appList.add(new SelectAppItem(packageInfo));
        }

        SelectAppAdapter adapter = new SelectAppAdapter(R.layout.select_app_recycler_item, appList,
                item -> {
                    popupWindow.dismiss();
                    Message msg = new Message(); msg.obj = item;
                    selectAppCallback.sendMessage(msg);
                }
        );
        RecyclerView select_app_recycler_view = (RecyclerView) view.findViewById(R.id.select_app_recycler_view);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(activity);
        linearLayoutManager.setOrientation(LinearLayoutManager.VERTICAL);
        select_app_recycler_view.setLayoutManager(linearLayoutManager);
        select_app_recycler_view.setAdapter(adapter);

        // 获取正在运行的APP
        String runningApp = NativeBridge.getAllCmdlineProcess(rootKey);
        Map<Integer, String> processMap = parseProcessInfo(runningApp);
        TextView clear_search_btn = view.findViewById(R.id.clear_search_btn);
        EditText search_edit = view.findViewById(R.id.search_edit);
        CheckBox show_system_app_ckbox = view.findViewById(R.id.show_system_app_ckbox);
        CheckBox show_thirty_app_ckbox = view.findViewById(R.id.show_thirty_app_ckbox);
        CheckBox show_running_app_ckbox = view.findViewById(R.id.show_running_app_ckbox);
        show_system_app_ckbox.setEnabled(true);
        show_thirty_app_ckbox.setEnabled(true);
        show_running_app_ckbox.setEnabled(true);
        Map<Integer, String> finalProcessMap = processMap;
        @SuppressLint("HandlerLeak") Handler updateAppListFunc = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                List<SelectAppItem> newAppList = new ArrayList<>();
                String filterText = search_edit.getText().toString();
                for(SelectAppItem item : appList) {
                    PackageInfo pack = item.getPackageInfo();
                    if(!show_system_app_ckbox.isChecked()) {
                        if ((pack.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue; //系统应用
                    }
                    if(!show_thirty_app_ckbox.isChecked()) {
                        if ((pack.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) == 0) continue; // 第三方应用
                    }
                    if (show_running_app_ckbox.isChecked()) {
                        boolean isFound = finalProcessMap.values().stream().anyMatch(value -> value.contains(item.getPackageName()));
                        if (!isFound) continue;
                    }
                    if(item.getPackageName().indexOf(filterText) != -1 || item.getShowName(activity).indexOf(filterText) != -1) newAppList.add(item);
                }
                adapter.setData(newAppList);
                super.handleMessage(msg);
            }
        };
        search_edit.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                clear_search_btn.setVisibility(s.toString().length() > 0 ? View.VISIBLE : View.GONE);
                updateAppListFunc.sendMessage(new Message());
            }
            @Override
            public void afterTextChanged(Editable s) {}
        });
        clear_search_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) { search_edit.setText(""); }
        });

        show_system_app_ckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) { updateAppListFunc.sendMessage(new Message()); }
        });
        show_thirty_app_ckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) { updateAppListFunc.sendMessage(new Message()); }
        });
        show_running_app_ckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) { updateAppListFunc.sendMessage(new Message()); }
        });
        updateAppListFunc.sendMessage(new Message());
        return view;
    }

    private static Map<Integer, String> parseProcessInfo(String jsonStr) {
        Map<Integer, String> processMap = new HashMap<>();
        try {
            JSONArray jsonArray = new JSONArray(jsonStr);
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject jsonObject = jsonArray.getJSONObject(i);
                int pid = jsonObject.getInt("pid");
                String encodedValue = jsonObject.getString("name");
                String name = URLDecoder.decode(encodedValue, "UTF-8");
                processMap.put(pid, name);
            }
        } catch (Exception e) { e.printStackTrace(); }
        return processMap;
    }
}
