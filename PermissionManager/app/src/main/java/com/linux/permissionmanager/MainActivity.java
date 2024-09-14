package com.linux.permissionmanager;

import android.annotation.SuppressLint;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.Adapter.SelectAppRecyclerAdapter;
import com.linux.permissionmanager.Adapter.SelectFileRecyclerAdapter;
import com.linux.permissionmanager.Model.PopupWindowOnTouchClose;
import com.linux.permissionmanager.Model.SelectAppRecyclerItem;
import com.linux.permissionmanager.Model.SelectFileRecyclerItem;
import com.linux.permissionmanager.Utils.ScreenInfoUtils;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URLDecoder;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    private String rootKey = "bz4kKoPVSAG1tnwlcs1PJ1qp6HtVymj60CoTgsjmMd1UALve";
    private String suBasePath = "/data/local/tmp";
    private String lastInputCmd = "id";
    private SharedPreferences m_shareSave;
    private ProgressDialog m_loadingDlg = null;
    private final String[] RECOMMEND_FILES = {"libc++_shared.so"};

    static {
        System.loadLibrary("permissionmanager");
    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        m_shareSave = getSharedPreferences("zhcs", Context.MODE_PRIVATE);
        try {
            rootKey = m_shareSave.getString("rootKey", rootKey);
        } catch (Exception e) {
        }
        try {
            lastInputCmd = m_shareSave.getString("lastInputCmd", lastInputCmd);
        } catch (Exception e) {
        }

        showUserInputRootKeyDlg();
        
        Button test_root_btn = findViewById(R.id.test_root_btn);
        Button run_root_cmd_btn = findViewById(R.id.run_root_cmd_btn);
        Button run_init_process_cmd_btn = findViewById(R.id.run_init_process_cmd_btn);
        Button su_env_install_btn = findViewById(R.id.su_env_install_btn);
        Button su_env_inject_btn = findViewById(R.id.su_env_inject_btn);
        Button clean_su_btn = findViewById(R.id.clean_su_btn);
        Button implant_app_btn = findViewById(R.id.implant_app_btn);
        Button copy_info_btn = findViewById(R.id.copy_info_btn);
        Button clean_info_btn = findViewById(R.id.clean_info_btn);
        
        test_root_btn.setOnClickListener(this);
        run_root_cmd_btn.setOnClickListener(this);
        run_init_process_cmd_btn.setOnClickListener(this);
        su_env_install_btn.setOnClickListener(this);
        su_env_inject_btn.setOnClickListener(this);
        clean_su_btn.setOnClickListener(this);
        implant_app_btn.setOnClickListener(this);
        copy_info_btn.setOnClickListener(this);
        clean_info_btn.setOnClickListener(this);
        
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.test_root_btn:
                appendConsoleMsg(testRoot(rootKey));
                break;
            case R.id.run_root_cmd_btn:
                showUserInputRootCmdDlg(false);
                break;
            case R.id.run_init_process_cmd_btn:
                showUserInputRootCmdDlg(true);
                break;
            case R.id.su_env_install_btn:
                onClickSuEnvInstallBtn();
                break;
            case R.id.su_env_inject_btn:
                showSelectSuInjectModeDlg();
                break;
            case R.id.clean_su_btn:
                appendConsoleMsg(uninstallSu(rootKey,suBasePath));
                break;
            case R.id.implant_app_btn:
                onClickImplantAppBtn();
                break;
            case R.id.copy_info_btn:
                copyConsoleMsg();
                break;
            case R.id.clean_info_btn:
                cleanConsoleMsg();
                break;
            default:
                break;
        }
    }
    public void showUserInputRootKeyDlg() {
        Handler inputCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                String inputTxt = (String)msg.obj;
                rootKey = inputTxt;
                SharedPreferences.Editor mEdit = m_shareSave.edit();
                mEdit.putString("rootKey", rootKey);
                mEdit.commit();
                super.handleMessage(msg);
            }
        };
        showInputDlg(rootKey,"请输入ROOT权限的KEY", inputCallback);
    }

    public void showUserInputRootCmdDlg(boolean isKernelCmd) {
        Handler inputCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                String inputTxt = (String)msg.obj;
                lastInputCmd = inputTxt;
                SharedPreferences.Editor mEdit = m_shareSave.edit();
                mEdit.putString("lastInputCmd", lastInputCmd);
                mEdit.commit();
                appendConsoleMsg(inputTxt + "\n"
                        + (isKernelCmd ?  runInit64ProcessCmd(rootKey, inputTxt) : runRootCmd(rootKey, inputTxt)));
                super.handleMessage(msg);
            }
        };
        
        showInputDlg(lastInputCmd, isKernelCmd ? "输入ROOT命令" : "输入普通命令", inputCallback);
    }

    public void showInputDlg(String defaultText, String title, Handler confirmCallback) {
        final EditText inputTxt = new EditText(MainActivity.this);
        inputTxt.setText(defaultText);
        inputTxt.setFocusable(true);
        inputTxt.setSelection(defaultText.length(), 0);
        AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
        builder.setTitle(title).setIcon(android.R.drawable.ic_dialog_info).setView(inputTxt)
                .setNegativeButton("取消", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                });
        builder.setPositiveButton("确定", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                String text = inputTxt.getText().toString();
                Message  msg = new Message();
                msg.obj = text;
                confirmCallback.sendMessage(msg);
            }
        });
        AlertDialog dialog = builder.create();
        dialog.show();
    }

    private void showMsgDlg(String title, String msg, Drawable icon) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(title);
        builder.setMessage(msg);
        if(icon != null) {
            builder.setIcon(icon);
        }
        builder.setPositiveButton("确定", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int id) {
                dialog.dismiss();
            }
        });
        AlertDialog dialog = builder.create();
        dialog.show();
    }

    public void onClickSuEnvInstallBtn() {
        //1.安装su工具
        String insRet = installSu(rootKey, suBasePath);
        appendConsoleMsg(insRet);
        if(insRet.indexOf("installSu done.") != -1) {
            //2.复制su的路径到剪贴板
            String suFullPath = getLastInstallSuFullPath();
            appendConsoleMsg("lastInstallSuFullPath:" + suFullPath);
            showMsgDlg("温馨提示",
                    "安装部署su成功，su路径已复制到剪贴板。", null);
            copyEditText(suFullPath);
            appendConsoleMsg("安装部署su成功，su路径已复制到剪贴板");
        }
    }

    private void suTempInject() {
        Handler selectInjectSuAppCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {

                SelectAppRecyclerItem appItem = (SelectAppRecyclerItem) msg.obj;

                if (m_loadingDlg == null) {
                    m_loadingDlg = new ProgressDialog(MainActivity.this);
                    m_loadingDlg.setCancelable(false);
                }
                m_loadingDlg.setTitle("");
                m_loadingDlg.setMessage("请现在手动启动APP [" + appItem.getShowName(MainActivity.this) + "]");
                m_loadingDlg.show();

                new Thread() {
                    public void run() {
                        String autoSuEnvInjectRet = autoSuEnvInject(rootKey, appItem.getPackageName());
                        runOnUiThread(new Runnable() {
                            public void run() {
                                appendConsoleMsg(autoSuEnvInjectRet);
                                m_loadingDlg.cancel();

                                if(autoSuEnvInjectRet.indexOf("autoSuEnvInject done.")!= -1) {
                                    showMsgDlg("提示",
                                            "已授予ROOT权限至APP [" + appItem.getShowName(MainActivity.this) + "]",
                                            appItem.getDrawable(MainActivity.this));
                                }

                            }
                        });
                    }
                }.start();
                super.handleMessage(msg);
            }
        };
        showSelectAppDlg(selectInjectSuAppCallback);
    }

    private void suForeverInject() {
        Handler selectImplantSuEnvCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                SelectAppRecyclerItem appItem = (SelectAppRecyclerItem) msg.obj;
                if (m_loadingDlg == null) {
                    m_loadingDlg = new ProgressDialog(MainActivity.this);
                    m_loadingDlg.setCancelable(false);
                }
                m_loadingDlg.setTitle("");
                m_loadingDlg.setMessage("请现在手动启动APP [" + appItem.getShowName(MainActivity.this) + "]");
                m_loadingDlg.show();
                new Thread() {
                    public void run() {
                        String parasitePrecheckAppRet = parasitePrecheckApp(rootKey, appItem.getPackageName());
                        runOnUiThread(new Runnable() {
                            public void run() {
                                m_loadingDlg.cancel();
                                Map<String, Integer> fileList = parseSoFullPathInfo(parasitePrecheckAppRet);
                                if (fileList.size() == 0 && !parasitePrecheckAppRet.isEmpty()) {
                                    appendConsoleMsg(parasitePrecheckAppRet);
                                    return;
                                }
                                Handler selectFileCallback = new Handler() {
                                    @Override
                                    public void handleMessage(@NonNull Message msg) {
                                        SelectFileRecyclerItem fileItem = (SelectFileRecyclerItem) msg.obj;
                                        String parasiteImplantSuEnvRet = parasiteImplantSuEnv(rootKey, appItem.getPackageName(), fileItem.getFilePath());
                                        appendConsoleMsg(parasiteImplantSuEnvRet);
                                        if(parasiteImplantSuEnvRet.indexOf("parasiteImplantSuEnv done.")!= -1) {
                                            showMsgDlg("提示",
                                                    "已永久寄生su环境至APP [" + appItem.getShowName(MainActivity.this) + "]",
                                                    appItem.getDrawable(MainActivity.this));
                                        }
                                        super.handleMessage(msg);
                                    }
                                };
                                showSelectFileDlg(fileList, selectFileCallback);
                            }
                        });
                    }
                }.start();
                super.handleMessage(msg);
            }
        };
        View view = showSelectAppDlg(selectImplantSuEnvCallback);
        CheckBox show_system_app_ckbox = view.findViewById(R.id.show_system_app_ckbox);
        CheckBox show_thirty_app_ckbox = view.findViewById(R.id.show_thirty_app_ckbox);
        CheckBox show_running_app_ckbox = view.findViewById(R.id.show_running_app_ckbox);
        show_system_app_ckbox.setChecked(false);
        show_system_app_ckbox.setEnabled(false);

        show_thirty_app_ckbox.setChecked(true);
        show_thirty_app_ckbox.setEnabled(false);

        show_running_app_ckbox.setChecked(true);
        show_running_app_ckbox.setEnabled(false);
    }

    public void showSelectSuInjectModeDlg() {
        final String[] items = {"临时授权su", "永久授权su"};
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("请选择一个选项");
        builder.setSingleChoiceItems(items, -1, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
                if(which == 0) {
                    suTempInject();
                } else if(which == 1) {
                    suForeverInject();
                }
            }
        });
        builder.setNegativeButton("取消", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
            }
        });
        AlertDialog dialog = builder.create();
        dialog.show();
    }

    public void onClickImplantAppBtn() {
        showMsgDlg("建议", "为了实现最佳隐蔽性，推荐寄生到能常驻后台且联网的APP上，如音乐类、播放器类、运动类、广播类、社交聊天类APP", null);
        Handler selectImplantAppCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                SelectAppRecyclerItem appItem = (SelectAppRecyclerItem) msg.obj;
                if (m_loadingDlg == null) {
                    m_loadingDlg = new ProgressDialog(MainActivity.this);
                    m_loadingDlg.setCancelable(false);
                }
                m_loadingDlg.setTitle("");
                m_loadingDlg.setMessage("请现在手动启动APP [" + appItem.getShowName(MainActivity.this) + "]");
                m_loadingDlg.show();
                new Thread() {
                    public void run() {
                        String parasitePrecheckAppRet = parasitePrecheckApp(rootKey, appItem.getPackageName());
                        runOnUiThread(new Runnable() {
                            public void run() {
                                m_loadingDlg.cancel();
                                Map<String, Integer> fileList = parseSoFullPathInfo(parasitePrecheckAppRet);
                                if (fileList.size() == 0 && !parasitePrecheckAppRet.isEmpty()) {
                                    appendConsoleMsg(parasitePrecheckAppRet);
                                    return;
                                }
                                Handler selectFileCallback = new Handler() {
                                    @Override
                                    public void handleMessage(@NonNull Message msg) {
                                        SelectFileRecyclerItem fileItem = (SelectFileRecyclerItem) msg.obj;
                                        String parasiteImplantAppRet = parasiteImplantApp(rootKey, appItem.getPackageName(), fileItem.getFilePath());
                                        appendConsoleMsg(parasiteImplantAppRet);
                                        if(parasiteImplantAppRet.indexOf("parasiteImplantApp done.")!= -1) {
                                            showMsgDlg("提示",
                                                    "已经寄生到APP [" + appItem.getShowName(MainActivity.this) + "]",
                                                    appItem.getDrawable(MainActivity.this));
                                        }
                                        super.handleMessage(msg);
                                    }
                                };
                                showSelectFileDlg(fileList, selectFileCallback);
                            }
                        });
                    }
                }.start();
                super.handleMessage(msg);
            }
        };
        View view = showSelectAppDlg(selectImplantAppCallback);
        CheckBox show_system_app_ckbox = view.findViewById(R.id.show_system_app_ckbox);
        CheckBox show_thirty_app_ckbox = view.findViewById(R.id.show_thirty_app_ckbox);
        CheckBox show_running_app_ckbox = view.findViewById(R.id.show_running_app_ckbox);
        show_system_app_ckbox.setChecked(false);
        show_system_app_ckbox.setEnabled(false);
        show_thirty_app_ckbox.setChecked(true);
        show_thirty_app_ckbox.setEnabled(false);
        show_running_app_ckbox.setChecked(true);
        show_running_app_ckbox.setEnabled(false);
    }

    public void appendConsoleMsg(String msg) {
        EditText console_edit = findViewById(R.id.console_edit);
        StringBuffer txt = new StringBuffer();
        txt.append(console_edit.getText().toString());
        if (txt.length() != 0) {
            txt.append("\n");
        }
        txt.append(msg);
        txt.append("\n");
        console_edit.setText(txt.toString());
        console_edit.setSelection(txt.length());
    }

    public void copyConsoleMsg() {
        EditText edit = findViewById(R.id.console_edit);
        copyEditText(edit.getText().toString());
        Toast.makeText(this, "复制成功", Toast.LENGTH_SHORT).show();
    }

    public void cleanConsoleMsg() {
        EditText console_edit = findViewById(R.id.console_edit);
        console_edit.setText("");
    }

    public void copyEditText(String text) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData mClipData = ClipData.newPlainText("Label", text);
        cm.setPrimaryClip(mClipData);
    }

    public View showSelectAppDlg(Handler selectAppCallback) {
        final PopupWindow popupWindow = new PopupWindow(this);

        View view = View.inflate(this, R.layout.select_app_wnd, null);
        popupWindow.setContentView(view);

        popupWindow.setHeight(ViewGroup.LayoutParams.MATCH_PARENT);
        popupWindow.setWidth(ViewGroup.LayoutParams.MATCH_PARENT);
        popupWindow.setBackgroundDrawable(new ColorDrawable(0x9B000000));
        popupWindow.setOutsideTouchable(true);
        popupWindow.setFocusable(true);
        popupWindow.setTouchable(true);

        //全屏
        View parent = View.inflate(MainActivity.this, R.layout.activity_main, null);
        popupWindow.showAtLocation(parent, Gravity.NO_GRAVITY, 0, 0);
        popupWindow.showAsDropDown(parent, 0, 0);

        popupWindow.setOnDismissListener(new PopupWindow.OnDismissListener() {
            @Override
            public void onDismiss() {
            }
        });

        final int screenWidth = ScreenInfoUtils.getRealWidth(this);
        final int screenHeight = ScreenInfoUtils.getRealHeight(this);

        final double centerWidth = ((double) screenWidth) * 0.80;
        final double centerHeight = ((double) screenHeight) * 0.90;

        LinearLayout center_layout = (LinearLayout) view.findViewById(R.id.center_layout);
        android.view.ViewGroup.LayoutParams lp = center_layout.getLayoutParams();
        lp.width = (int) centerWidth;
        lp.height = (int) centerHeight;

        //点击阴影部分可关闭窗口
        popupWindow.setTouchInterceptor(new PopupWindowOnTouchClose(popupWindow,
                screenWidth, screenHeight, (int) centerWidth, (int) centerHeight));

        List<SelectAppRecyclerItem> appList = new ArrayList<>();
        List<PackageInfo> packages = getPackageManager().getInstalledPackages(0);

        for (int i = 0; i < packages.size(); i++) {
            PackageInfo packageInfo = packages.get(i);
            String packageName = packageInfo.applicationInfo.packageName;
            if(packageName.equals(getPackageName())){
                continue;
            }
            appList.add(new SelectAppRecyclerItem(packageInfo));
        }

        SelectAppRecyclerAdapter adapter = new SelectAppRecyclerAdapter(
                MainActivity.this, R.layout.select_app_recycler_item, appList, popupWindow, selectAppCallback);
        RecyclerView select_app_recycler_view = (RecyclerView) view.findViewById(R.id.select_app_recycler_view);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this);
        linearLayoutManager.setOrientation(LinearLayoutManager.VERTICAL);
        select_app_recycler_view.setLayoutManager(linearLayoutManager);
        select_app_recycler_view.setAdapter(adapter);

        // 获取正在运行的APP
        String runningApp = getAllCmdlineProcess(rootKey);
        Map<Integer, String> processMap = parseProcessInfo(runningApp);
        if(processMap.size() == 0 && !runningApp.isEmpty()) {
            appendConsoleMsg(runningApp);
        }

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
                List<SelectAppRecyclerItem> newAppList = new ArrayList<>();
                String filterText = search_edit.getText().toString();
                for(SelectAppRecyclerItem item : appList) {
                    PackageInfo pack = item.getPackageInfo();
                    if(!show_system_app_ckbox.isChecked()) {
                        if ((pack.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0) {  //系统应用
                            continue;
                        }
                    }
                    if(!show_thirty_app_ckbox.isChecked()) {
                        if ((pack.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) == 0) { //第三方应用
                            continue;
                        }
                    }
                    if (show_running_app_ckbox.isChecked()) {
                        boolean isFound = finalProcessMap.values().stream()
                                .anyMatch(value -> value.contains(item.getPackageName()));
                        if (!isFound) {
                            continue;
                        }
                    }
                    if(item.getPackageName().indexOf(filterText) != -1 || item.getShowName(MainActivity.this).indexOf(filterText) != -1) {
                        newAppList.add(item);
                    }
                }
                adapter.updateList(newAppList);
                super.handleMessage(msg);
            }
        };
        search_edit.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }
            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                String text = s.toString();
                if(text.length() > 0) {
                    clear_search_btn.setVisibility(View.VISIBLE);
                } else {
                    clear_search_btn.setVisibility(View.GONE);
                }
                updateAppListFunc.sendMessage(new Message());
            }
            @Override
            public void afterTextChanged(Editable s) {
            }
        });
        clear_search_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                search_edit.setText("");
            }
        });

        show_system_app_ckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                updateAppListFunc.sendMessage(new Message());
            }
        });
        show_thirty_app_ckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                updateAppListFunc.sendMessage(new Message());
            }
        });
        show_running_app_ckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                updateAppListFunc.sendMessage(new Message());
            }
        });
        updateAppListFunc.sendMessage(new Message());
        return view;
    }

    private boolean checkIsRecommendFile(String filePath) {
        Path path = Paths.get(filePath);
        String fileName = path.getFileName().toString();
        for (String recommendFile : RECOMMEND_FILES) {
            if (recommendFile.equals(fileName)) {
                return true;
            }
        }
        return false;
    }

    public View showSelectFileDlg(Map<String, Integer> filePath, Handler selectFileCallback) {
        final PopupWindow popupWindow = new PopupWindow(this);

        View view = View.inflate(this, R.layout.select_file_wnd, null);
        popupWindow.setContentView(view);

        popupWindow.setHeight(ViewGroup.LayoutParams.MATCH_PARENT);
        popupWindow.setWidth(ViewGroup.LayoutParams.MATCH_PARENT);
        popupWindow.setBackgroundDrawable(new ColorDrawable(0x9B000000));
        popupWindow.setOutsideTouchable(true);
        popupWindow.setFocusable(true);
        popupWindow.setTouchable(true);

        //全屏
        View parent = View.inflate(MainActivity.this, R.layout.activity_main, null);
        popupWindow.showAtLocation(parent, Gravity.NO_GRAVITY, 0, 0);
        popupWindow.showAsDropDown(parent, 0, 0);

        popupWindow.setOnDismissListener(new PopupWindow.OnDismissListener() {
            @Override
            public void onDismiss() {
            }
        });

        final int screenWidth = ScreenInfoUtils.getRealWidth(this);
        final int screenHeight = ScreenInfoUtils.getRealHeight(this);

        final double centerWidth = ((double) screenWidth) * 0.80;
        final double centerHeight = ((double) screenHeight) * 0.90;

        LinearLayout center_layout = (LinearLayout) view.findViewById(R.id.center_layout);
        android.view.ViewGroup.LayoutParams lp = center_layout.getLayoutParams();
        lp.width = (int) centerWidth;
        lp.height = (int) centerHeight;

        //点击阴影部分可关闭窗口
        popupWindow.setTouchInterceptor(new PopupWindowOnTouchClose(popupWindow,
                screenWidth, screenHeight, (int) centerWidth, (int) centerHeight));

        List<SelectFileRecyclerItem> fileList = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : filePath.entrySet()) {
            String strFilePath = entry.getKey();
            Integer status = entry.getValue();
            if(status != 1) {
                continue;
            }
            String strFileDesc = checkIsRecommendFile(strFilePath) ? "(推荐，正在运行)" :  "(正在运行)";
            fileList.add(new SelectFileRecyclerItem(strFilePath, strFileDesc, Color.valueOf(0xFFFFFFFF)));
        }
        for (Map.Entry<String, Integer> entry : filePath.entrySet()) {
            String strFilePath = entry.getKey();
            Integer status = entry.getValue();
            if(status != 2) {
                continue;
            }
            String strFileDesc ="(未运行)";
            fileList.add(new SelectFileRecyclerItem(strFilePath, strFileDesc, Color.valueOf(Color.GRAY)));
        }

        SelectFileRecyclerAdapter adapter = new SelectFileRecyclerAdapter(
                MainActivity.this, R.layout.select_file_recycler_item, fileList, popupWindow, selectFileCallback);
        RecyclerView select_file_recycler_view = (RecyclerView) view.findViewById(R.id.select_file_recycler_view);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this);
        linearLayoutManager.setOrientation(LinearLayoutManager.VERTICAL);
        select_file_recycler_view.setLayoutManager(linearLayoutManager);
        select_file_recycler_view.setAdapter(adapter);

        TextView clear_search_btn = view.findViewById(R.id.clear_search_btn);
        EditText search_edit = view.findViewById(R.id.search_edit);

        @SuppressLint("HandlerLeak") Handler updateFileListFunc = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                List<SelectFileRecyclerItem> newFileList = new ArrayList<>();
                String filterText = search_edit.getText().toString();
                for(SelectFileRecyclerItem item : fileList) {
                    String fileName = item.getFileName();
                    if(fileName.indexOf(filterText) != -1) {
                        newFileList.add(item);
                    }
                }
                adapter.updateList(newFileList);
                super.handleMessage(msg);
            }
        };
        search_edit.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                String text = s.toString();
                if(text.length() > 0) {
                    clear_search_btn.setVisibility(View.VISIBLE);
                } else {
                    clear_search_btn.setVisibility(View.GONE);
                }
                updateFileListFunc.sendMessage(new Message());
            }

            @Override
            public void afterTextChanged(Editable s) {
            }
        });
        clear_search_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                search_edit.setText("");
            }
        });
        updateFileListFunc.sendMessage(new Message());
        return view;
    }

    private Map<Integer, String> parseProcessInfo(String jsonStr) {
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
        } catch (Exception e) {
            e.printStackTrace();
        }
        return processMap;
    }

    public Map<String, Integer> parseSoFullPathInfo(String jsonStr) {
        Map<String, Integer> soPathMap = new HashMap<>();
        try {
            JSONArray jsonArray = new JSONArray(jsonStr);
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject jsonObject = jsonArray.getJSONObject(i);
                String encodedValue = jsonObject.getString("name");
                String name = URLDecoder.decode(encodedValue, "UTF-8");
                int pid = jsonObject.getInt("status");
                soPathMap.put(name,pid);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return soPathMap;
    }

    public native String testRoot(String rootKey);

    public native String runRootCmd(String rootKey, String cmd);

    public native String runInit64ProcessCmd(String rootKey, String cmd);

    public native String installSu(String rootKey, String basePath);

    public native String getLastInstallSuFullPath();

    public native String uninstallSu(String rootKey, String basePath);

    public native String autoSuEnvInject(String rootKey, String targetProcessCmdline);

    public native String getAllCmdlineProcess(String rootKey);

    public native String parasitePrecheckApp(String rootKey, String targetProcessCmdline);

    public native String parasiteImplantApp(String rootKey, String targetProcessCmdline, String targetSoFullPath);

    public native String parasiteImplantSuEnv(String rootKey, String targetProcessCmdline, String targetSoFullPath);

}