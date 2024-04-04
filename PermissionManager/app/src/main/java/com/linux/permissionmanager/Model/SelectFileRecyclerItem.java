package com.linux.permissionmanager.Model;

import android.os.Build;

import androidx.annotation.RequiresApi;

import java.nio.file.Path;
import java.nio.file.Paths;

public class SelectFileRecyclerItem {
    private String filePath;

    public SelectFileRecyclerItem(String  filePath){
        this.filePath = filePath;
    }

    public String getFilePath() {
        return this.filePath;
    }

    public String getFileName() {
        Path path = Paths.get(filePath);
        Path fileName = path.getFileName();
        return fileName.toString();
    }
}
