package com.linux.permissionmanager;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.graphics.Paint;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.linux.permissionmanager.bridge.NativeBridge;
import com.linux.permissionmanager.helper.SelectAppDlg;
import com.linux.permissionmanager.helper.SelectFileDlg;
import com.linux.permissionmanager.model.SelectAppItem;
import com.linux.permissionmanager.model.SelectFileItem;
import com.linux.permissionmanager.utils.ClipboardUtils;
import com.linux.permissionmanager.utils.DialogUtils;
import com.linux.permissionmanager.utils.GetAppListPermissionHelper;
import com.linux.permissionmanager.utils.UrlIntentUtils;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    private String rootKey = "";
    private String lastInputCmd = "id";
    private String lastInputRootExecPath = "";
    private ProgressDialog m_loadingDlg = null;

	private EditText console_edit;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        AppSettings.init(this);

        rootKey = AppSettings.getString("rootKey", rootKey);
        lastInputCmd = AppSettings.getString("lastInputCmd", lastInputCmd);
        lastInputRootExecPath = AppSettings.getString("lastInputRootExecPath", lastInputRootExecPath);
        checkGetAppListPermission();
        showInputRootKeyDlg();

        Button test_root_btn = findViewById(R.id.test_root_btn);
        Button run_root_cmd_btn = findViewById(R.id.run_root_cmd_btn);
        Button root_exec_process_btn = findViewById(R.id.root_exec_process_btn);
        Button su_env_install_btn = findViewById(R.id.su_env_install_btn);
        Button su_env_inject_btn = findViewById(R.id.su_env_inject_btn);
        Button clean_su_btn = findViewById(R.id.clean_su_btn);
        Button implant_app_btn = findViewById(R.id.implant_app_btn);
        Button copy_info_btn = findViewById(R.id.copy_info_btn);
        Button clean_info_btn = findViewById(R.id.clean_info_btn);
        console_edit = findViewById(R.id.console_edit);

        test_root_btn.setOnClickListener(this);
        run_root_cmd_btn.setOnClickListener(this);
        root_exec_process_btn.setOnClickListener(this);
        su_env_install_btn.setOnClickListener(this);
        su_env_inject_btn.setOnClickListener(this);
        clean_su_btn.setOnClickListener(this);
        implant_app_btn.setOnClickListener(this);
        copy_info_btn.setOnClickListener(this);
        clean_info_btn.setOnClickListener(this);
        initLink();
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.test_root_btn:
                appendConsoleMsg(NativeBridge.testRoot(rootKey));
                break;
            case R.id.run_root_cmd_btn:
                showInputRootCmdDlg();
                break;
            case R.id.root_exec_process_btn:
                showInputRootExecProcessPathDlg();
                break;
            case R.id.su_env_install_btn:
                onClickSuEnvInstallBtn();
                break;
            case R.id.su_env_inject_btn:
                showSelectSuInjectModeDlg();
                break;
            case R.id.clean_su_btn:
                onClickSuEnvUninstallBtn();
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

    private void initLink() {
        TextView link_tv = findViewById(R.id.link_tv);
        link_tv.setText("https://github.com/abcz316/SKRoot-linuxKernelRoot");
        link_tv.setOnClickListener(v -> { UrlIntentUtils.openUrl(this, link_tv.getText().toString()); });
        link_tv.getPaint().setFlags(link_tv.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);
    }

    private void showSkrootStatus() {
        appendConsoleMsg("版本：" + BuildConfig.VERSION_NAME);
    }

    public void showInputRootKeyDlg() {
        Handler inputCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                String text = (String)msg.obj;
                rootKey = text;
                AppSettings.setString("rootKey", rootKey);
                showSkrootStatus();
                super.handleMessage(msg);
            }
        };
        DialogUtils.showInputDlg(this, rootKey,"请输入ROOT权限的KEY", null, inputCallback, null);
    }
    private void checkGetAppListPermission() {
        if(GetAppListPermissionHelper.getPermissions(this)) return;
        DialogUtils.showCustomDialog(this,"权限申请","请授予读取APP列表权限，再重新打开",null,"确定", (dialog, which) -> {
                    dialog.dismiss();
                    finish();
                },null, null
        );
    }

    public void showInputRootCmdDlg() {
        Handler inputCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                String text = (String)msg.obj;
                lastInputCmd = text;
                AppSettings.setString("lastInputCmd", lastInputCmd);
                appendConsoleMsg(text + "\n" + NativeBridge.runRootCmd(rootKey, text));
                super.handleMessage(msg);
            }
        };
        DialogUtils.showInputDlg(this, lastInputCmd, "请输入ROOT命令", null, inputCallback, null);
    }

    public void showInputRootExecProcessPathDlg() {
        Handler inputCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                String text = (String)msg.obj;

                lastInputRootExecPath = text;
                AppSettings.setString("lastInputRootExecPath", lastInputRootExecPath);
                appendConsoleMsg(text + "\n" + NativeBridge.rootExecProcessCmd(rootKey, text));
                super.handleMessage(msg);
            }
        };
        Handler helperCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                DialogUtils.showMsgDlg(MainActivity.this,"帮助", "请将JNI可执行文件放入/data内任意目录并且赋予777权限，如/data/app/com.xx，然后输入文件路径，即可直接执行，如：\n/data/com.xx/aaa\n", null);
                super.handleMessage(msg);
            }
        };
        DialogUtils.showInputDlg(this, lastInputRootExecPath, "请输入Linux可运行文件的位置", "指导", inputCallback, helperCallback);
        DialogUtils.showMsgDlg(this,"提示", "本功能是以ROOT身份直接运行程序，可避免产生su、sh等多余驻留后台进程，能最大程度上避免侦测", null);
    }

    public void onClickSuEnvInstallBtn() {
        String insRet = NativeBridge.installSu(rootKey);
        appendConsoleMsg(insRet);
        if(insRet.indexOf("install_su done.") != -1) {
            String suFilePath = NativeBridge.getLastSuFilePath();
            appendConsoleMsg("last_su_file_path:" + suFilePath);
            DialogUtils.showMsgDlg(this,"温馨提示","安装部署su成功，su路径已复制到剪贴板。", null);
            ClipboardUtils.copyText(this, suFilePath);
            appendConsoleMsg("安装部署su成功，su路径已复制到剪贴板");
        }
    }

    public void onClickSuEnvUninstallBtn() {
        appendConsoleMsg(NativeBridge.uninstallSu(rootKey));
        ClipboardUtils.copyText(this, "");
    }

    private void suTempInject() {
        Handler selectInjectSuAppCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                SelectAppItem app = (SelectAppItem) msg.obj;
                if (m_loadingDlg == null) {
                    m_loadingDlg = new ProgressDialog(MainActivity.this);
                    m_loadingDlg.setCancelable(false);
                }
                m_loadingDlg.setTitle("");
                m_loadingDlg.setMessage("请现在手动启动APP [" + app.getShowName(MainActivity.this) + "]");
                m_loadingDlg.show();
                startSuTempInjectThread(app);
                super.handleMessage(msg);
            }
        };
        SelectAppDlg.showSelectAppDlg(MainActivity.this, rootKey, selectInjectSuAppCallback);
    }

    private void startSuTempInjectThread(SelectAppItem app) {
        new Thread() {
            public void run() {
                String autoSuEnvInjectRet = NativeBridge.autoSuEnvInject(rootKey, app.getPackageName());
                runOnUiThread(new Runnable() {
                    public void run() {
                        appendConsoleMsg(autoSuEnvInjectRet);
                        m_loadingDlg.cancel();

                        if(autoSuEnvInjectRet.indexOf("auto_su_env_inject done.") != -1) {
                            DialogUtils.showMsgDlg(MainActivity.this, "提示","已授予ROOT权限至APP [" + app.getShowName(MainActivity.this) + "]",
                                    app.getDrawable(MainActivity.this));
                        }
                    }
                });
            }
        }.start();
    }

    private void suForeverInject() {
        Handler selectImplantSuEnvCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                SelectAppItem app = (SelectAppItem) msg.obj;
                if (m_loadingDlg == null) {
                    m_loadingDlg = new ProgressDialog(MainActivity.this);
                    m_loadingDlg.setCancelable(false);
                }
                m_loadingDlg.setTitle("");
                m_loadingDlg.setMessage("请现在手动启动APP [" + app.getShowName(MainActivity.this) + "]");
                m_loadingDlg.show();
                startSuForeverInjectThread(app);
                super.handleMessage(msg);
            }
        };
        View view = SelectAppDlg.showSelectAppDlg(MainActivity.this, rootKey, selectImplantSuEnvCallback);
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

    private void startSuForeverInjectThread(SelectAppItem app) {
        new Thread() {
            public void run() {
                String parasitePrecheckAppRet = NativeBridge.parasitePrecheckApp(rootKey, app.getPackageName());
                runOnUiThread(new Runnable() {
                    public void run() {
                        m_loadingDlg.cancel();
                        Map<String, SelectFileDlg.FileStatus> fileList = parseSoFullPathInfo(parasitePrecheckAppRet);
                        if (fileList.size() == 0 && !parasitePrecheckAppRet.isEmpty()) {
                            appendConsoleMsg(parasitePrecheckAppRet);
                            return;
                        }
                        Handler selectFileCallback = new Handler() {
                            @Override
                            public void handleMessage(@NonNull Message msg) {
                                SelectFileItem fileItem = (SelectFileItem) msg.obj;
                                String parasiteImplantSuEnvRet = NativeBridge.parasiteImplantSuEnv(rootKey, app.getPackageName(), fileItem.getFilePath());
                                appendConsoleMsg(parasiteImplantSuEnvRet);
                                if(parasiteImplantSuEnvRet.indexOf("parasite_implant_su_env done.")!= -1) {
                                    DialogUtils.showMsgDlg(MainActivity.this, "提示","已永久寄生su环境至APP [" + app.getShowName(MainActivity.this) + "]",
                                            app.getDrawable(MainActivity.this));
                                }
                                super.handleMessage(msg);
                            }
                        };
                        SelectFileDlg.showSelectFileDlg(MainActivity.this, fileList, selectFileCallback);
                    }
                });
            }
        }.start();
    }

    public void showSelectSuInjectModeDlg() {
        final String[] items = {"临时授权su", "永久授权su"};
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("请选择一个选项");
        builder.setSingleChoiceItems(items, -1, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
                if(which == 0) suTempInject();
                else if(which == 1) suForeverInject();
            }
        });
        builder.setNegativeButton("取消", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) { dialog.dismiss(); }
        });
        AlertDialog dialog = builder.create();
        dialog.show();
    }


    private void onClickImplantAppBtn() {
        Handler selectImplantAppCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                SelectAppItem app = (SelectAppItem) msg.obj;
                if (m_loadingDlg == null) {
                    m_loadingDlg = new ProgressDialog(MainActivity.this);
                    m_loadingDlg.setCancelable(false);
                }
                m_loadingDlg.setTitle("");
                m_loadingDlg.setMessage("请现在手动启动APP [" + app.getShowName(MainActivity.this) + "]");
                m_loadingDlg.show();
                startImplantAppThread(app);
                super.handleMessage(msg);
            }
        };
        View view = SelectAppDlg.showSelectAppDlg(MainActivity.this, rootKey, selectImplantAppCallback);
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

    private void startImplantAppThread(SelectAppItem app) {
        new Thread() {
            public void run() {
                String parasitePrecheckAppRet = NativeBridge.parasitePrecheckApp(rootKey, app.getPackageName());
                runOnUiThread(new Runnable() {
                    public void run() {
                        m_loadingDlg.cancel();
                        Map<String, SelectFileDlg.FileStatus> fileList = parseSoFullPathInfo(parasitePrecheckAppRet);
                        if (fileList.size() == 0 && !parasitePrecheckAppRet.isEmpty()) {
                            appendConsoleMsg(parasitePrecheckAppRet);
                            return;
                        }
                        Handler selectFileCallback = new Handler() {
                            @Override
                            public void handleMessage(@NonNull Message msg) {
                                SelectFileItem fileItem = (SelectFileItem) msg.obj;
                                String parasiteImplantAppRet = NativeBridge.parasiteImplantApp(rootKey, app.getPackageName(), fileItem.getFilePath());
                                appendConsoleMsg(parasiteImplantAppRet);
                                if(parasiteImplantAppRet.indexOf("parasite_implant_app done.")!= -1) {
                                    DialogUtils.showMsgDlg(MainActivity.this, "提示",
                                            "已经寄生到APP [" + app.getShowName(MainActivity.this) + "]",
                                            app.getDrawable(MainActivity.this));
                                }
                                super.handleMessage(msg);
                            }
                        };
                        SelectFileDlg.showSelectFileDlg(MainActivity.this, fileList, selectFileCallback);
                    }
                });
            }
        }.start();
    }

    private void appendConsoleMsg(String msg) {
        StringBuffer txt = new StringBuffer();
        txt.append(console_edit.getText().toString());
        if (txt.length() != 0) txt.append("\n");
        txt.append(msg);
        txt.append("\n");
        console_edit.setText(txt.toString());
        console_edit.setSelection(txt.length());
    }

    public void copyConsoleMsg() {
        ClipboardUtils.copyText(this, console_edit.getText().toString());
        Toast.makeText(this, "复制成功", Toast.LENGTH_SHORT).show();
    }

    public void cleanConsoleMsg() {
        console_edit.setText("");
    }

    private Map<String, SelectFileDlg.FileStatus> parseSoFullPathInfo(String jsonStr) {
        Map<String, SelectFileDlg.FileStatus> soPathMap = new HashMap<>();
        try {
            JSONArray jsonArray = new JSONArray(jsonStr);
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject jsonObject = jsonArray.getJSONObject(i);
                String name = URLDecoder.decode(jsonObject.getString("name"), "UTF-8");
                int n = jsonObject.getInt("status");
                SelectFileDlg.FileStatus status =  SelectFileDlg.FileStatus.Unknown;
                status = n == 1 ?  SelectFileDlg.FileStatus.Running : status;
                status = n == 2 ?  SelectFileDlg.FileStatus.NotRunning : status;
                soPathMap.put(name, status);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return soPathMap;
    }

}