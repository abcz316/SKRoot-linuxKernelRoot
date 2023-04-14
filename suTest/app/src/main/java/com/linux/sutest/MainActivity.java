package com.linux.sutest;

import androidx.appcompat.app.AppCompatActivity;

import android.graphics.Color;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

public class MainActivity extends AppCompatActivity {



    //执行root命令
    public static final String runRootCmd(String cmd, boolean bWait) {
        String retval = "";
        try {
            Process process = Runtime.getRuntime().exec("su");
            DataOutputStream os = new DataOutputStream(process.getOutputStream());
            os.writeBytes(cmd + "\n");
            os.flush();
            os.writeBytes("exit\n");
            os.flush();
            if (bWait) {
                process.waitFor();
            } else {
                Thread.sleep(300);
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    process.getInputStream()));
            int read;
            char[] buffer = new char[4096];
            StringBuffer output = new StringBuffer();
            while ((read = reader.read(buffer)) > 0) {
                output.append(buffer, 0, read);
            }
            reader.close();
            reader = new BufferedReader(new InputStreamReader(
                    process.getErrorStream()));
            while ((read = reader.read(buffer)) > 0) {
                output.append(buffer, 0, read);
            }
            reader.close();

            try {
        /*
        int suProcessRetval = process.waitFor();
        if (255 != suProcessRetval) {
            retval = true;
        } else {
            retval = false;
        }
        */
                retval = output.toString();
            } catch (Exception ex) {
                //Log.e("Error executing root action", ex);
            }
        } catch (IOException ex) {
            //Log.w("ROOT", "Can't get root access", ex);
        } catch (SecurityException ex) {
            //Log.w("ROOT", "Can't get root access", ex);
        } catch (Exception ex) {
            //Log.w("ROOT", "Error executing internal operation", ex);
        }
        return retval;
    }

    //检查是否具有Root权限
    public boolean canRunRootCommands() {
        String suTest = runRootCmd("id", true);
        if (suTest.contains("uid=0")) {
            return true;
        }
        return false;
    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        updateRootStatus();
        Button test_root_btn = findViewById(R.id.test_root_btn);
        test_root_btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                updateRootStatus();
            }
        });

    }
    private void updateRootStatus(){
        //获取ROOT权限检查
        TextView root_status_txt = findViewById(R.id.root_status_txt);
        if (canRunRootCommands()) {
            root_status_txt.setText("获取成功");
            root_status_txt.setTextColor(Color.rgb(0,255,0));
        } else{
            root_status_txt.setText("获取失败");
            root_status_txt.setTextColor(Color.rgb(255,0,0));
        }
    }
}