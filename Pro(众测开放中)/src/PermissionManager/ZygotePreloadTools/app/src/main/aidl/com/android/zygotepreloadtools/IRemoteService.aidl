package com.android.zygotepreloadtools;

import com.android.zygotepreloadtools.IRemoteProcess;

interface IRemoteService {
    IRemoteProcess getRemoteProcess();
}