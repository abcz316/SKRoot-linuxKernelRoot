package com.linux.permissionmanager.adapter;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Message;
import android.text.Html;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.PopupWindow;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.model.SelectAppItem;
import com.linux.permissionmanager.R;

import java.util.ArrayList;
import java.util.List;

public class SelectAppRecyclerAdapter extends RecyclerView.Adapter<SelectAppRecyclerAdapter.ViewHolder> {
    public static class ViewHolder extends RecyclerView.ViewHolder {
        public View v;
        public ImageView select_app_icon;
        public TextView select_app_text;
        public TextView select_package_name;
        public ViewHolder(View v) {
            super(v);
            this.v = v;
        }

    }

    private int resourceId;
    private List<SelectAppItem> objects;
    private PopupWindow popupWindow;
    private Handler selectAppCallback;
    private Context ctx;
    public SelectAppRecyclerAdapter(Context ctx, int textViewResourceId, List<SelectAppItem> objects, PopupWindow popupWindow, Handler selectAppCallback) {
        this.resourceId = textViewResourceId;
        this.objects = new ArrayList<>(objects);
        this. popupWindow = popupWindow;
        this. selectAppCallback = selectAppCallback;
        this. ctx = ctx;
    }

    public void updateList(List<SelectAppItem> newList) {
        objects.clear();
        objects.addAll(newList);
        notifyDataSetChanged();
    }


    public List<SelectAppItem> getList() {
        return objects;
    }


    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v =LayoutInflater.from(parent.getContext()).inflate(resourceId,parent,false);
       SelectAppRecyclerAdapter.ViewHolder holder = new SelectAppRecyclerAdapter.ViewHolder(v);

        holder.select_app_icon = v.findViewById(R.id.select_app_icon);
        holder.select_app_text=v.findViewById(R.id.select_app_text) ;
        holder.select_package_name=v.findViewById(R.id.select_package_name) ;
        return holder;
    }


    @Override
    public void onBindViewHolder(@NonNull SelectAppRecyclerAdapter.ViewHolder holder, int position) {
        SelectAppItem appItem=objects.get(position);
        String showName = appItem.getShowName(ctx);
        String packageName = appItem.getPackageName();
        Drawable icon = appItem.getDrawable(ctx);

        //图标+进程PID+名字+内存
        holder.select_app_icon.setImageDrawable(icon);
        String  showText="<font color = \"#88CC88\">"+showName +"</font> "
                +" <font color = \"#88CCCC\">"+" ("+packageName+")"+"</font>";

        holder.select_app_text.setText(Html.fromHtml(showText));
        holder.select_package_name.setText(packageName);

        //item被点击
        holder.v.setOnClickListener(new ClickRecyclerItemListener(appItem));
    }


    @Override
    public int getItemCount() {
        return objects.size();
    }

    @Override
    public int getItemViewType(int position) {
        return position;
    }


    class ClickRecyclerItemListener implements View.OnClickListener {
        SelectAppItem appItem;
        public ClickRecyclerItemListener( SelectAppItem appItem){
            this.appItem =appItem;
        }
        @Override
        public void onClick(View v) {
            popupWindow.dismiss();
            Message msg = new Message();
            msg.obj = (SelectAppItem)appItem;
            selectAppCallback.sendMessage(msg);
        }
    }
}
