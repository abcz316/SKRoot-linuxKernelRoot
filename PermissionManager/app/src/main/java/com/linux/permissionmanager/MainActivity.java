package com.linux.permissionmanager;

import android.app.Activity;
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
import android.graphics.PixelFormat;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
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
import com.linux.permissionmanager.Model.PopupWindowOnTouchClose;
import com.linux.permissionmanager.Model.SelectAppRecyclerItem;
import com.linux.permissionmanager.Utils.ScreenInfoUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private String rootKey = "mUBcNll4mhenWlvYEWZF4yOHm5aOPklyq0LAUIAbV0L7R0Ub";
    private String suBasePath = "/data/local/tmp";
    private String lastInputCmd = "id";

    //保存的本地配置信息
    private SharedPreferences m_shareSave;
    private ProgressDialog m_loadingDlg = null;

    // Used to load the 'permissionmanager' library on application startup.
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

        //验证用户的KEY
        final EditText inputKey = new EditText(MainActivity.this);
        inputKey.setText(rootKey);
        AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
        builder.setCancelable(false);
        builder.setTitle("请输入ROOT权限的KEY").setIcon(android.R.drawable.ic_dialog_info).setView(inputKey)
                .setPositiveButton("确定", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        rootKey = inputKey.getText().toString();
                        //数值保存到本地
                        SharedPreferences.Editor mEdit = m_shareSave.edit();
                        mEdit.putString("rootKey", rootKey);
                        mEdit.commit();
                    }
                });
        builder.show();


        Button test_root_btn = findViewById(R.id.test_root_btn);
        test_root_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showConsoleMsg(testRoot(rootKey));
            }
        });

        Button run_root_cmd_btn = findViewById(R.id.run_root_cmd_btn);
        run_root_cmd_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final EditText inputCMD = new EditText(MainActivity.this);
                inputCMD.setText(lastInputCmd);
                inputCMD.setFocusable(true);
                inputCMD.setSelection(inputCMD.length(), 0);
                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                builder.setTitle("输入普通命令").setIcon(android.R.drawable.ic_dialog_info).setView(inputCMD)
                        .setNegativeButton("取消", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                dialog.dismiss();
                            }
                        });
                builder.setPositiveButton("确定", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        String text = inputCMD.getText().toString();
                        lastInputCmd = text;
                        showConsoleMsg(text + "\n" + runRootCmd(rootKey, text));
                    }
                });
                builder.show();

            }
        });
        Button run_init_process_cmd_btn = findViewById(R.id.run_init_process_cmd_btn);
        run_init_process_cmd_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final EditText inputCMD = new EditText(MainActivity.this);
                inputCMD.setText(lastInputCmd);
                inputCMD.setFocusable(true);
                inputCMD.setSelection(inputCMD.length(), 0);
                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                builder.setTitle("输入ROOT命令").setIcon(android.R.drawable.ic_dialog_info).setView(inputCMD)
                        .setNegativeButton("取消", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                dialog.dismiss();
                            }
                        });
                builder.setPositiveButton("确定", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        String text = inputCMD.getText().toString();
                        lastInputCmd = text;
                        showConsoleMsg(text + "\n" + runInit64ProcessCmd(rootKey, text));
                    }
                });
                builder.show();

            }
        });

        Button su_env_install_btn = findViewById(R.id.su_env_install_btn);
        su_env_install_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //1.获取su工具文件路径
                String suOriginalFilePath = WirteSuToolsFilePath("su", MainActivity.this);
                showConsoleMsg("su origin path:"+ suOriginalFilePath);

                //2.安装su工具
                String insRet = installSu(rootKey, suBasePath, suOriginalFilePath);
                showConsoleMsg(insRet);
                if(insRet.indexOf("installSu done.") == -1) {
                    return;
                }

                //3.复制su的路径到剪贴板
                String suFullPath = getLastInstallSuFullPath();
                showConsoleMsg("lastInstallSuFullPath:" + suFullPath);
                copyEditText(suFullPath);
                Toast.makeText(v.getContext(), "su路径已复制到剪贴板", Toast.LENGTH_SHORT).show();

            }
        });

        Button su_env_inject_btn = findViewById(R.id.su_env_inject_btn);
        su_env_inject_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showSelectAppWindow();
            }
        });

        Button clean_su_btn = findViewById(R.id.clean_su_btn);
        clean_su_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                showConsoleMsg(uninstallSu(rootKey,suBasePath));
            }
        });

        Button copy_info_btn = findViewById(R.id.copy_info_btn);
        copy_info_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                EditText edit = findViewById(R.id.console_edit);
                copyEditText(edit.getText().toString());
                Toast.makeText(v.getContext(), "复制成功", Toast.LENGTH_SHORT).show();

            }
        });
        Button clean_info_btn = findViewById(R.id.clean_info_btn);
        clean_info_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                cleanConsoleMsg();
            }
        });
    }

    public void showConsoleMsg(String msg) {
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

    public void cleanConsoleMsg() {
        EditText console_edit = findViewById(R.id.console_edit);
        console_edit.setText("");
    }

    public void copyEditText(String text) {
        //获取剪贴板管理器：
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        // 创建普通字符型ClipData
        ClipData mClipData = ClipData.newPlainText("Label", text);
        // 将ClipData内容放到系统剪贴板里。
        cm.setPrimaryClip(mClipData);

    }

    Handler selectAppItemCallback = new Handler() {
        @Override
        public void handleMessage(@NonNull Message msg) {

            SelectAppRecyclerItem appItem = (SelectAppRecyclerItem) msg.obj;

            if (m_loadingDlg == null) {
                m_loadingDlg = new ProgressDialog(MainActivity.this);
                m_loadingDlg.setCancelable(false);
            }
            m_loadingDlg.setTitle("");
            m_loadingDlg.setMessage("请现在手动启动APP [" + appItem.getShowName() + "]");
            m_loadingDlg.show();

            new Thread() {
                public void run() {
                    String ret = autoSuEnvInject(rootKey, appItem.getPackageName());
                    runOnUiThread(new Runnable() {
                        public void run() {
                            showConsoleMsg(ret);
                            m_loadingDlg.cancel();

                            if(ret.indexOf("autoSuEnvInject done.")!= -1) {
                                //弹个提示，通知一下成功了
                                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this)
                                        .setCancelable(false)
                                        .setTitle("提示")
                                        .setIcon(appItem.getIcon())
                                        .setMessage("已经授予ROOT权限到APP [" + appItem.getShowName() + "]")
                                        .setNegativeButton("确定", new DialogInterface.OnClickListener() {
                                            @Override
                                            public void onClick(DialogInterface dialog, int which) {
                                                dialog.dismiss();
                                            }
                                        });
                                AlertDialog dialog = builder.create();
                                dialog.show();
                                dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(Color.BLACK);
                            }

                        }
                    });
                }
            }.start();
            super.handleMessage(msg);
        }
    };

    //显示选择应用程序窗口
    public void showSelectAppWindow() {
        final PopupWindow popupWindow = new PopupWindow(this);

        View view = View.inflate(this, R.layout.select_app_wnd, null);
        popupWindow.setContentView(view);

        popupWindow.setHeight(ViewGroup.LayoutParams.MATCH_PARENT);
        popupWindow.setWidth(ViewGroup.LayoutParams.MATCH_PARENT);
        popupWindow.setBackgroundDrawable(new ColorDrawable(0x9B000000)); //阴影半透明
        popupWindow.setOutsideTouchable(true);
        popupWindow.setFocusable(true);
        popupWindow.setTouchable(true);

        //全屏
        View parent = View.inflate(MainActivity.this, R.layout.activity_main, null);
        popupWindow.showAtLocation(parent, Gravity.NO_GRAVITY, 0, 0);
        popupWindow.showAsDropDown(parent, 0, 0);

        popupWindow.setOnDismissListener(new PopupWindow.OnDismissListener() {
            @Override
            public void onDismiss() { //窗口即将关闭

            }
        });

        //设置中心布局大小
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

        //显示APP列表
        List<SelectAppRecyclerItem> appList = new ArrayList<>();

        //获取已安装的APK列表
        List<PackageInfo> packages = getPackageManager().getInstalledPackages(0);

        //先判断cmdline与包名是否完全相同
        for (int i = 0; i < packages.size(); i++) {
            PackageInfo packageInfo = packages.get(i);

            if ((packageInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0) {
                //系统应用
                continue;
            }
            String showName = packageInfo.applicationInfo.loadLabel(getPackageManager()).toString();

            Drawable icon = packageInfo.applicationInfo.loadIcon(getPackageManager());

            String packageName = packageInfo.applicationInfo.packageName;
            if(packageName.equals(getPackageName())){
                //不显示自己
                continue;
            }
            //加入到显示APP列表
            appList.add(new SelectAppRecyclerItem(
                    icon,
                    showName,
                    packageName));
        }
        for (int i = 0; i < packages.size(); i++) {
            PackageInfo packageInfo = packages.get(i);

            if ((packageInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) == 0) {
                //非系统应用
                continue;
            }

            String showName = packageInfo.applicationInfo.loadLabel(getPackageManager()).toString();

            Drawable icon = packageInfo.applicationInfo.loadIcon(getPackageManager());

            String packageName = packageInfo.applicationInfo.packageName;

            //加入到显示APP列表
            appList.add(new SelectAppRecyclerItem(
                    icon,
                    showName,
                    packageName));
        }

        SelectAppRecyclerAdapter adapter = new SelectAppRecyclerAdapter(
                MainActivity.this, R.layout.select_app_recycler_item, appList, popupWindow, selectAppItemCallback);

        RecyclerView select_app_recycler_view = (RecyclerView) view.findViewById(R.id.select_app_recycler_view);
        // 设置布局管理器
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this);
        linearLayoutManager.setOrientation(LinearLayoutManager.VERTICAL);
        select_app_recycler_view.setLayoutManager(linearLayoutManager);
        select_app_recycler_view.setAdapter(adapter);

    }

    public static String WirteSuToolsFilePath(String suName, Context context) {
        String suFilePath = "";
        try {
            suFilePath = context.getFilesDir().getPath() + "/" + suName;
            File file = new File(suFilePath);
            if (!file.exists()) {
                if (!file.getParentFile().exists()) file.getParentFile().mkdirs();
                file.createNewFile();
            }
            if (file.exists()) {
                InputStream inputStream = context.getAssets().open(suName);
                FileOutputStream outputStream = new FileOutputStream(file);
                byte[] content = new byte[1024];
                while (inputStream.read(content) > 0) {
                    outputStream.write(content);
                }
                inputStream.close();
                outputStream.flush();
                outputStream.close();
            }
        } catch (Exception e) {
        }
        return suFilePath;
    }

    public native String testRoot(String rootKey);

    public native String runRootCmd(String rootKey, String cmd);

    public native String runInit64ProcessCmd(String rootKey, String cmd);

    public native String installSu(String rootKey, String basePath, String originSuFullPath);

    public native String getLastInstallSuFullPath();

    public native String uninstallSu(String rootKey, String basePath);

    public native String autoSuEnvInject(String rootKey, String targetProcessCmdline);
}