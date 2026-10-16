package com.linux.permissionmanager.utils.repack;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;
import com.linux.permissionmanager.utils.AppCertUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

/** 随机 RSA / X.509 自签名证书 + apksig 签名与验签。 */
final class ApkRandomSigner {
    private ApkRandomSigner() {}

    static void signAndVerify(File unsignedApk, File signedApk, byte[] subject) throws Exception {
        KeyAndCert identity = createRandomSigningKey(subject);
        ApkSigner.SignerConfig config = new ApkSigner.SignerConfig.Builder(
                identity.alias, identity.privateKey, identity.certificates).build();
        new ApkSigner.Builder(Collections.singletonList(config))
                .setInputApk(unsignedApk).setOutputApk(signedApk)
                .setV1SigningEnabled(true).setV2SigningEnabled(true).setV3SigningEnabled(true)
                .setOtherSignersSignaturesPreserved(false).build().sign();
        ApkVerifier.Result result = new ApkVerifier.Builder(signedApk).build().verify();
        if (!result.isVerified()) throw new IOException("APK 签名验证失败: " + result.getErrors());
    }

    /** 使用 X.509 Subject 的六个可配置字段构建 RDNSequence（DER）。 */
    static byte[] encodeCertificateSubject(AppCertUtils.CertInfo info) throws IOException {
        if (info == null) throw new IllegalArgumentException("certInfo 不能为 null");
        String cn = validateSubjectField("CN", info.certCN, 64, true);
        String o = validateSubjectField("O", info.certO, 64, false);
        String ou = validateSubjectField("OU", info.certOU, 64, false);
        String l = validateSubjectField("L", info.certL, 128, false);
        String st = validateSubjectField("ST", info.certST, 128, false);
        String c = validateSubjectField("C", info.certC, 2, false);
        if (c != null) {
            c = c.toUpperCase(Locale.ROOT);
            if (!c.matches("[A-Za-z0-9]{2}")) throw new IllegalArgumentException("证书国家C必须是两个英文字母或数字: " + c);
        }

        // X.509 RDNSequence 从外到内编码，因此多数解析器的 RFC2253 输出顺序相反。
        ByteArrayOutputStream rdns = new ByteArrayOutputStream();
        appendSubjectRdn(rdns, 0x06, c, true);   // 2.5.4.6 countryName (PrintableString)
        appendSubjectRdn(rdns, 0x08, st, false); // 2.5.4.8 stateOrProvinceName
        appendSubjectRdn(rdns, 0x07, l, false);  // 2.5.4.7 localityName
        appendSubjectRdn(rdns, 0x0a, o, false);  // 2.5.4.10 organizationName
        appendSubjectRdn(rdns, 0x0b, ou, false); // 2.5.4.11 organizationalUnitName
        appendSubjectRdn(rdns, 0x03, cn, false); // 2.5.4.3 commonName
        return Der.value(0x30, rdns.toByteArray());
    }

    private static String validateSubjectField(String field, String text, int maxLength, boolean required) {
        if (text == null || text.isEmpty()) {
            if (required) throw new IllegalArgumentException("证书 CN 不能为空");
            return null;
        }
        if (text.length() > maxLength) {
            throw new IllegalArgumentException("证书 " + field + " 长度不能超过 " + maxLength + " 个字符");
        }
        if (text.trim().isEmpty()) throw new IllegalArgumentException("证书 " + field + " 不能只有空白字符");
        for (int i = 0; i < text.length(); i++) {
            if (Character.isISOControl(text.charAt(i))) {
                throw new IllegalArgumentException("证书 " + field + " 不能包含控制字符");
            }
        }
        return text;
    }

    private static void appendSubjectRdn(ByteArrayOutputStream out, int oidLastByte,
                                          String text, boolean printableString) throws IOException {
        if (text == null) return;
        byte[] encoded = printableString ? text.getBytes(StandardCharsets.US_ASCII)
                : text.getBytes(StandardCharsets.UTF_8);
        byte[] rdn = Der.value(0x31, Der.sequence(
                Der.value(0x06, new byte[]{0x55, 0x04, (byte) oidLastByte}),
                Der.value(printableString ? 0x13 : 0x0c, encoded)));
        out.write(rdn, 0, rdn.length);
    }

    /** 仅使用 Android/Java 标准密码学 API；不依赖 JKS、Bouncy Castle 或 sun.security.x509。 */
    private static KeyAndCert createRandomSigningKey(byte[] distinguishedName) throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, random);
        KeyPair keyPair = generator.generateKeyPair();

        byte[] signatureAlgorithm = Der.sequence(
                Der.value(0x06, new byte[]{0x2a, (byte) 0x86, 0x48, (byte) 0x86,
                        (byte) 0xf7, 0x0d, 0x01, 0x01, 0x0b}), // 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
                Der.value(0x05, new byte[0])); // NULL algorithm parameters

        byte[] serialBytes = new byte[16];
        random.nextBytes(serialBytes);
        serialBytes[0] &= 0x7f; // serial 正整数
        serialBytes[0] |= 0x01; // 非零
        BigInteger serial = new BigInteger(1, serialBytes);

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 24L * 60 * 60 * 1000);
        Date notAfter = new Date(now + 30L * 365 * 24 * 60 * 60 * 1000);
        byte[] validity = Der.sequence(Der.time(notBefore), Der.time(notAfter));
        byte[] tbsCertificate = Der.sequence(
                Der.value(0xa0, Der.value(0x02, BigInteger.valueOf(2).toByteArray())), // v3
                Der.value(0x02, serial.toByteArray()),
                signatureAlgorithm,
                distinguishedName,
                validity,
                distinguishedName,
                keyPair.getPublic().getEncoded()); // SubjectPublicKeyInfo (标准 X.509 DER)

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate(), random);
        signature.update(tbsCertificate);
        byte[] signed = signature.sign();
        byte[] bitString = new byte[signed.length + 1];
        System.arraycopy(signed, 0, bitString, 1, signed.length); // 首字节 unused bits=0
        byte[] encodedCertificate = Der.sequence(tbsCertificate, signatureAlgorithm,
                Der.value(0x03, bitString));
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(encodedCertificate));
        certificate.checkValidity();
        certificate.verify(keyPair.getPublic());
        return new KeyAndCert("random", keyPair.getPrivate(), Collections.singletonList(certificate));
    }

    /** DER 编码器，仅覆盖生成上述自签名 X.509 证书所需的 ASN.1 类型。 */
    private static final class Der {
        static byte[] sequence(byte[]... parts) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (byte[] part : parts) out.write(part, 0, part.length);
            return value(0x30, out.toByteArray());
        }

        static byte[] value(int tag, byte[] data) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream(data.length + 8);
            out.write(tag);
            int length = data.length;
            if (length < 128) {
                out.write(length);
            } else {
                int byteCount = 0;
                for (int n = length; n != 0; n >>>= 8) byteCount++;
                out.write(0x80 | byteCount);
                for (int shift = (byteCount - 1) * 8; shift >= 0; shift -= 8) {
                    out.write((length >>> shift) & 0xff);
                }
            }
            out.write(data, 0, data.length);
            return out.toByteArray();
        }

        static byte[] time(Date date) throws IOException {
            SimpleDateFormat yearFormat = new SimpleDateFormat("yyyy", Locale.US);
            yearFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
            int year = Integer.parseInt(yearFormat.format(date));
            boolean generalized = year < 1950 || year >= 2050;
            SimpleDateFormat fmt = new SimpleDateFormat(
                    generalized ? "yyyyMMddHHmmss'Z'" : "yyMMddHHmmss'Z'", Locale.US);
            fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
            return value(generalized ? 0x18 : 0x17,
                    fmt.format(date).getBytes(StandardCharsets.US_ASCII));
        }
    }

    private static final class KeyAndCert {
        final String alias;
        final PrivateKey privateKey;
        final List<X509Certificate> certificates;
        KeyAndCert(String alias, PrivateKey privateKey, List<X509Certificate> certificates) {
            this.alias = alias;
            this.privateKey = privateKey;
            this.certificates = certificates;
        }
    }

}
