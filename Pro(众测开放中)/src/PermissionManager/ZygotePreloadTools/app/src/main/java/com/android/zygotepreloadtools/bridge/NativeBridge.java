package com.android.zygotepreloadtools.bridge;

public final class NativeBridge {
    static { System.loadLibrary("zygotepreloadtools"); }

    public static native String testSkrootBasics(String rootKey, String item);
    public static native String oneplusBypassWriteStage1();
}