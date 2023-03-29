package com.linux.permissionmanager.Model;

import android.view.MotionEvent;
import android.view.View;
import android.widget.PopupWindow;

public class PopupWindowOnTouchClose implements View.OnTouchListener {
    private boolean lastVailedDown = true;
    private int screenWidth, screenHeight, centerWidth, centerHeight;
    private PopupWindow popupWindow;

    public PopupWindowOnTouchClose(PopupWindow popupWindow, int screenWidth, int screenHeight, int centerWidth, int centerHeight) {
        this.popupWindow = popupWindow;
        this.screenWidth = screenWidth;
        this.screenHeight = screenHeight;
        this.centerWidth = centerWidth;
        this.centerHeight = centerHeight;
    }

    private boolean isValiedRegion(View v, MotionEvent event) {
        int x = (int) event.getX();
        int y = (int) event.getY();
        double wndLeft = (screenWidth - centerWidth) / 2;
        double wndTop = (screenHeight - centerHeight) / 2;
        if (x < wndLeft || x > wndLeft + centerWidth || y < wndTop || y > wndTop + centerHeight) {
            return false;
        }
        return true;
    }

    @Override
    public boolean onTouch(View v, MotionEvent event) {

        if (event.getAction() == MotionEvent.ACTION_DOWN) {
            lastVailedDown = isValiedRegion(v, event);
        } else if (event.getAction() == MotionEvent.ACTION_UP) {
            if (!lastVailedDown) {
                if (!isValiedRegion(v, event)) {
                    popupWindow.dismiss();
                }
            }
        }
        return false;
    }
}



