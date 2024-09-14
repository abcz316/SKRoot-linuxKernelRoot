package com.linux.permissionmanager.Model;

import android.graphics.Color;
import android.os.Build;

import androidx.annotation.RequiresApi;

import java.nio.file.Path;
import java.nio.file.Paths;

public class SelectFileRecyclerItem {
    private String filePath;
    private String fileDesc;
    private Color fileDescColor;

    public SelectFileRecyclerItem(String filePath, String fileDesc, Color fileDescColor){
        this.filePath = filePath;
        this.fileDesc = fileDesc;
        this.fileDescColor = fileDescColor;
    }

    public String getFilePath() {
        return this.filePath;
    }

    public String getFileName() {
        Path path = Paths.get(filePath);
        Path fileName = path.getFileName();
        return fileName.toString();
    }
    public String getFileDesc() {
        return this.fileDesc;
    }
    public Color getFileDescColor() {
        return this.fileDescColor;
    }
}
