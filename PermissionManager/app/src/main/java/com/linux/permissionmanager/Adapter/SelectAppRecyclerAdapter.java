package com.linux.permissionmanager.Adapter;

import android.content.Context;
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

import com.linux.permissionmanager.Model.SelectAppRecyclerItem;
import com.linux.permissionmanager.R;

import java.util.List;

public class SelectAppRecyclerAdapter extends RecyclerView.Adapter<SelectAppRecyclerAdapter.ViewHolder> {



    public static class ViewHolder extends RecyclerView.ViewHolder {
        public View v;
        public ImageView select_app_icon;
        public TextView select_app_text;
        public TextView select_package_name;
        // TODO Auto-generated method stub
        public ViewHolder(View v) {
            super(v);
            this.v = v;
        }

    }

    private int resourceId;
    private List<SelectAppRecyclerItem> objects;
    private PopupWindow popupWindow;
    private Handler selectAppItemCallback;
    public SelectAppRecyclerAdapter(Context context, int textViewResourceId, List<SelectAppRecyclerItem> objects, PopupWindow popupWindow, Handler selectAppItemCallback) {
        this.resourceId = textViewResourceId;
        this.objects = objects;
        this. popupWindow = popupWindow;
        this. selectAppItemCallback = selectAppItemCallback;
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
        SelectAppRecyclerItem appItem=objects.get(position);           //获取当前项的实例

        //图标+进程PID+名字+内存
        holder.select_app_icon.setImageDrawable(appItem.getIcon());
        String  showText="<font color = \"#88CC88\">"+appItem.getShowName() +"</font> "
                +" <font color = \"#88CCCC\">"+" ("+appItem.getPackageName()+")"+"</font>";

        holder.select_app_text.setText(Html.fromHtml(showText));
        holder.select_package_name.setText(appItem.getPackageName());

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
        SelectAppRecyclerItem appItem;
        public ClickRecyclerItemListener( SelectAppRecyclerItem appItem){
            this.appItem =appItem;
        }
        @Override
        public void onClick(View v) {
            popupWindow.dismiss();
            Message msg = new Message();
            msg.obj = (SelectAppRecyclerItem)appItem;
            selectAppItemCallback.sendMessage(msg);
        }
    }




}
