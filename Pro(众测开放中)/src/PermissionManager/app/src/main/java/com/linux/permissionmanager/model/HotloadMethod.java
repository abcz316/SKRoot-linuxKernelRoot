package com.linux.permissionmanager.model;
public enum HotloadMethod {
    NONE(""),
    MAGICA("MAGICA"),   // 对应 CVE-2026-24088
    SHELL("SHELL"),
    CVE_2026_43499("CVE-2026-43499"),
    CVE_2026_43284("CVE-2026-43284"),
    CVE_2026_98260("CVE-2026-98260");
    private final String configValue;
    HotloadMethod(String configValue) { this.configValue = configValue; }
    public String getConfigValue() { return configValue; }
    public static HotloadMethod fromConfig(String value) {
        if (value == null || value.isEmpty()) return NONE;
        for (HotloadMethod m : values()) {
            if (m.configValue.equalsIgnoreCase(value)) return m;
        }
        return NONE;
    }
    public static final String SUPPORTED_CVE_TEXT = "CVE-2026-24088 / 43499 / 43284 / 98260";
}