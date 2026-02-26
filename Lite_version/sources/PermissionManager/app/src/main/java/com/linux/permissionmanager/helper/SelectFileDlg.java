package com.linux.permissionmanager.helper;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Handler;
import android.os.Message;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.adapter.SelectAppAdapter;
import com.linux.permissionmanager.adapter.SelectFileAdapter;
import com.linux.permissionmanager.model.SelectFileItem;
import com.linux.permissionmanager.utils.ScreenInfoUtils;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class SelectFileDlg {

    private static String[] RECOMMEND_FILES = {"libc++_shared.so"};

    public enum FileStatus {
        Unknown,
        Running,
        NotRunning,
    };
    public static View showSelectFileDlg(Activity activity, Map<String, FileStatus> filePath, Handler selectFileCallback) {
        final PopupWindow popupWindow = new PopupWindow(activity);
        View view = View.inflate(activity, R.layout.select_file_wnd, null);
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

        List<SelectFileItem> fileList = new ArrayList<>();
        for (Map.Entry<String, FileStatus> entry : filePath.entrySet()) {
            String strFilePath = entry.getKey();
            FileStatus status = entry.getValue();
            if(status != FileStatus.Running) continue;
            String strFileDesc = checkIsRecommendFile(strFilePath) ? "(推荐，正在运行)" :  "(正在运行)";
            fileList.add(new SelectFileItem(strFilePath, strFileDesc, Color.valueOf(0xFFFFFFFF)));
        }
        for (Map.Entry<String, FileStatus> entry : filePath.entrySet()) {
            String strFilePath = entry.getKey();
            FileStatus status = entry.getValue();
            if(status != FileStatus.NotRunning)  continue;
            String strFileDesc ="(未运行)";
            fileList.add(new SelectFileItem(strFilePath, strFileDesc, Color.valueOf(Color.GRAY)));
        }
        SelectFileAdapter adapter = new SelectFileAdapter(R.layout.select_file_recycler_item, fileList,
                item -> {
                    popupWindow.dismiss();
                    Message msg = new Message(); msg.obj = item;
                    selectFileCallback.sendMessage(msg);
                }
        );
        RecyclerView select_file_recycler_view = (RecyclerView) view.findViewById(R.id.select_file_recycler_view);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(activity);
        linearLayoutManager.setOrientation(LinearLayoutManager.VERTICAL);
        select_file_recycler_view.setLayoutManager(linearLayoutManager);
        select_file_recycler_view.setAdapter(adapter);
        TextView clear_search_btn = view.findViewById(R.id.clear_search_btn);
        EditText search_edit = view.findViewById(R.id.search_edit);
        @SuppressLint("HandlerLeak") Handler updateFileListFunc = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                List<SelectFileItem> newFileList = new ArrayList<>();
                String filterText = search_edit.getText().toString();
                for(SelectFileItem item : fileList) {
                    String fileName = item.getFileName();
                    if(fileName.indexOf(filterText) != -1)  newFileList.add(item);
                }
                adapter.setData(newFileList);
                super.handleMessage(msg);
            }
        };
        search_edit.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                clear_search_btn.setVisibility(s.toString().length() > 0 ? View.VISIBLE : View.GONE);
                updateFileListFunc.sendMessage(new Message());
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });
        clear_search_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) { search_edit.setText(""); }
        });
        updateFileListFunc.sendMessage(new Message());
        return view;
    }

    private static boolean checkIsRecommendFile(String filePath) {
        Path path = Paths.get(filePath);
        String fileName = path.getFileName().toString();
        for (String recommendFile : RECOMMEND_FILES) {
            if (recommendFile.equals(fileName)) return true;
        }
        return false;
    }

}
