package com.linux.permissionmanager.model;
public enum HotloadMethod {
    NONE(""),
    MAGICA("MAGICA"),
    SHELL("SHELL"),
    CVE_2026_43499("CVE-2026-43499"),
    CVE_2026_43284("CVE-2026-43284");
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
}