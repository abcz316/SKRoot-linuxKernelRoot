
package com.linux.permissionmanager.utils;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

public final class AppCertUtils {

    private AppCertUtils() {}

    public static class CertInfo {
        public String certCN = "";
        public String certO = "";
        public String certOU = "";
        public String certL = "";
        public String certST = "";
        public String certC = "";
    }

    public static CertInfo getCertInfo(Context context, String packageName) throws PackageManager.NameNotFoundException, CertificateException {

        PackageManager pm = context.getPackageManager();
        Signature[] signatures;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageInfo info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);
            signatures = info.signingInfo == null ? null : info.signingInfo.getApkContentsSigners();
        } else {
            PackageInfo info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
            signatures = info.signatures;
        }

        if (signatures == null || signatures.length == 0)
            throw new CertificateException("找不到签名证书");

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(signatures[0].toByteArray()));

        String dn = certificate.getSubjectX500Principal().getName(X500Principal.RFC2253);

        CertInfo result = new CertInfo();
        result.certCN = getField(dn, "CN");
        result.certO = getField(dn, "O");
        result.certOU = getField(dn, "OU");
        result.certL = getField(dn, "L");
        result.certST = getField(dn, "ST");
        result.certC = getField(dn, "C");
        if (result.certCN.isEmpty()) {
            result.certCN = !result.certO.isEmpty() ? result.certO : (!result.certOU.isEmpty() ? result.certOU : "Android");
        }
        return result;
    }

    private static String getField(String dn, String key) {
        int start = 0;
        boolean escaped = false;

        for (int i = 0; i <= dn.length(); i++) {
            if (i == dn.length() || (!escaped && (dn.charAt(i) == ',' || dn.charAt(i) == '+'))) {
                String part = dn.substring(start, i);
                int equal = part.indexOf('=');

                if (equal > 0 && part.substring(0, equal).trim().equalsIgnoreCase(key))
                    return unescape(part.substring(equal + 1));

                start = i + 1;
                escaped = false;
                continue;
            }

            escaped = dn.charAt(i) == '\\' && !escaped;
        }
        return "";
    }

    private static String unescape(String value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        for (int i = 0; i < value.length();) {
            if (value.charAt(i) == '\\' && i + 1 < value.length()) {
                if (i + 2 < value.length()) {
                    int hi = Character.digit(value.charAt(i + 1), 16);
                    int lo = Character.digit(value.charAt(i + 2), 16);
                    if (hi >= 0 && lo >= 0) {
                        out.write((hi << 4) | lo);
                        i += 3;
                        continue;
                    }
                }
                i++;
            }

            int cp = value.codePointAt(i);
            byte[] bytes = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8);
            out.write(bytes, 0, bytes.length);
            i += Character.charCount(cp);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }
}
