/*
 * Copyright (C) 2026 Ramirez Lima
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package rkr.simplekeyboard.inputmethod.crypto;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.FeatureInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import rkr.simplekeyboard.inputmethod.compat.PreferenceManagerCompat;

/**
 * Finds out, on this very device, where keys can live and which key agreements the secure
 * hardware performs by itself, so that private keys would never have to be in app memory.
 *
 * Feature flags alone do not tell which curves the chip implements, so every capability is
 * tested for real with throwaway keys: generate or import a key, ask the Keystore for a key
 * agreement, and check the result against the same computation in software.
 */
public final class KeystoreCapabilities {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String PREF_RESULT = "cifra_keystore_probe";
    private static final String PREF_FINGERPRINT = "cifra_keystore_probe_build";
    private static final String PROBE_ALIAS = "cifra_probe_";
    private static final byte[] X25519_PKCS8_PREFIX = Hex.decode("302e020100300506032b656e04220420");
    private static final byte[] X25519_SPKI_PREFIX = Hex.decode("302a300506032b656e032100");
    private static final ExecutorService sExecutor = Executors.newSingleThreadExecutor();

    /** Where a key ended up. */
    public enum Where {
        UNAVAILABLE,
        SOFTWARE,
        SECURE_HARDWARE,
        TEE,
        STRONGBOX;

        public boolean isHardware() {
            return this == SECURE_HARDWARE || this == TEE || this == STRONGBOX;
        }
    }

    /** Values of the system features, 0 when absent or unknown. */
    public int mKeyMintVersion;
    public int mStrongBoxVersion;
    public boolean mStrongBoxFeature;
    public Where mAesTee = Where.UNAVAILABLE;
    public Where mAesStrongBox = Where.UNAVAILABLE;
    public Where mX25519Generated = Where.UNAVAILABLE;
    public Where mX25519Imported = Where.UNAVAILABLE;
    public Where mP256GeneratedTee = Where.UNAVAILABLE;
    public Where mP256ImportedTee = Where.UNAVAILABLE;
    public Where mP256GeneratedStrongBox = Where.UNAVAILABLE;
    public Where mP256ImportedStrongBox = Where.UNAVAILABLE;

    public interface Callback {
        void onResult(KeystoreCapabilities capabilities);
    }

    /**
     * @return the stored result for this system build, or null if it was never measured.
     */
    public static KeystoreCapabilities load(final Context context) {
        final SharedPreferences prefs = PreferenceManagerCompat.getDeviceSharedPreferences(context);
        if (!Build.FINGERPRINT.equals(prefs.getString(PREF_FINGERPRINT, null))) {
            return null;
        }
        return fromString(prefs.getString(PREF_RESULT, null));
    }

    /**
     * Measures once per system build (a system update can change what the chip supports).
     */
    public static void ensureProbed(final Context context, final Callback callback) {
        final KeystoreCapabilities stored = load(context);
        if (stored != null) {
            if (callback != null) {
                callback.onResult(stored);
            }
            return;
        }
        probeAsync(context, callback);
    }

    public static void probeAsync(final Context context, final Callback callback) {
        final Context appContext = context.getApplicationContext();
        final android.os.Handler main = new android.os.Handler(android.os.Looper.getMainLooper());
        sExecutor.execute(() -> {
            final KeystoreCapabilities result = probe(appContext);
            PreferenceManagerCompat.getDeviceSharedPreferences(appContext).edit()
                    .putString(PREF_RESULT, result.toString())
                    .putString(PREF_FINGERPRINT, Build.FINGERPRINT)
                    .apply();
            if (callback != null) {
                main.post(() -> callback.onResult(result));
            }
        });
    }

    /**
     * The best place the current message format (X25519) could keep identity keys.
     */
    public Where bestForX25519() {
        return mX25519Imported;
    }

    public Where bestForP256() {
        if (mP256ImportedStrongBox == Where.STRONGBOX) {
            return Where.STRONGBOX;
        }
        return mP256ImportedTee;
    }

    // Probing

    static KeystoreCapabilities probe(final Context context) {
        final KeystoreCapabilities caps = new KeystoreCapabilities();
        readFeatures(context, caps);
        final boolean strongBoxApi = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P;
        caps.mAesTee = probeAes(false);
        if (strongBoxApi && caps.mStrongBoxFeature) {
            caps.mAesStrongBox = probeAes(true);
        }
        // Key agreement inside the Keystore exists from Android 12; X25519 from Android 13.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            caps.mP256GeneratedTee = probeP256Generated(false);
            caps.mP256ImportedTee = probeP256Imported(false);
            if (caps.mStrongBoxFeature) {
                caps.mP256GeneratedStrongBox = probeP256Generated(true);
                caps.mP256ImportedStrongBox = probeP256Imported(true);
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            caps.mX25519Generated = probeX25519Generated();
            caps.mX25519Imported = probeX25519Imported();
        }
        return caps;
    }

    private static void readFeatures(final Context context, final KeystoreCapabilities caps) {
        final PackageManager pm = context.getPackageManager();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            caps.mStrongBoxFeature = pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
        }
        final FeatureInfo[] features = pm.getSystemAvailableFeatures();
        if (features == null) {
            return;
        }
        for (final FeatureInfo feature : features) {
            if (feature.name == null) {
                continue;
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                    && feature.name.equals(PackageManager.FEATURE_HARDWARE_KEYSTORE)) {
                caps.mKeyMintVersion = feature.version;
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                    && feature.name.equals(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                caps.mStrongBoxVersion = feature.version;
            }
        }
    }

    private static Where probeAes(final boolean strongBox) {
        final String alias = PROBE_ALIAS + "aes";
        try {
            final KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                spec.setIsStrongBoxBacked(strongBox);
            }
            final KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                    ANDROID_KEYSTORE);
            generator.init(spec.build());
            return where(generator.generateKey(), strongBox);
        } catch (Exception | Error e) {
            return Where.UNAVAILABLE;
        } finally {
            delete(alias);
        }
    }

    private static Where probeP256Generated(final boolean strongBox) {
        final String alias = PROBE_ALIAS + "p256_gen";
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
            final KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_AGREE_KEY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"));
            spec.setIsStrongBoxBacked(strongBox);
            generator.initialize(spec.build());
            final KeyPair keystorePair = generator.generateKeyPair();
            if (!p256AgreementMatches(keystorePair.getPrivate(), keystorePair.getPublic())) {
                return Where.UNAVAILABLE;
            }
            return where(keystorePair.getPrivate(), strongBox);
        } catch (Exception | Error e) {
            return Where.UNAVAILABLE;
        } finally {
            delete(alias);
        }
    }

    private static Where probeP256Imported(final boolean strongBox) {
        final String alias = PROBE_ALIAS + "p256_imp";
        try {
            final KeyPair software = softwareP256();
            final X509Certificate certificate = certificate(
                    SubjectPublicKeyInfo.getInstance(software.getPublic().getEncoded()),
                    software.getPrivate());
            final KeyProtection.Builder protection = new KeyProtection.Builder(
                    KeyProperties.PURPOSE_AGREE_KEY);
            protection.setIsStrongBoxBacked(strongBox);
            final KeyStore keyStore = androidKeyStore();
            keyStore.setEntry(alias, new KeyStore.PrivateKeyEntry(software.getPrivate(),
                    new Certificate[] { certificate }), protection.build());
            final PrivateKey imported = (PrivateKey) keyStore.getKey(alias, null);
            if (!p256AgreementMatches(imported, software.getPublic())) {
                return Where.UNAVAILABLE;
            }
            return where(imported, strongBox);
        } catch (Exception | Error e) {
            return Where.UNAVAILABLE;
        } finally {
            delete(alias);
        }
    }

    private static Where probeX25519Generated() {
        final String alias = PROBE_ALIAS + "x25519_gen";
        try {
            // "XDH" (X25519) is registered by the Keystore provider from Android 13.
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("XDH",
                    ANDROID_KEYSTORE);
            generator.initialize(new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_AGREE_KEY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("x25519"))
                    .build());
            final KeyPair keystorePair = generator.generateKeyPair();
            final byte[] spki = keystorePair.getPublic().getEncoded();
            final byte[] publicKey = Arrays.copyOfRange(spki, spki.length - 32, spki.length);
            if (!x25519AgreementMatches(keystorePair.getPrivate(), publicKey)) {
                return Where.UNAVAILABLE;
            }
            return where(keystorePair.getPrivate(), false);
        } catch (Exception | Error e) {
            return Where.UNAVAILABLE;
        } finally {
            delete(alias);
        }
    }

    /**
     * The case that matters for Cifra: a key derived outside the chip (from BIP39 words) is
     * imported once and then used only through the Keystore.
     */
    private static Where probeX25519Imported() {
        final String alias = PROBE_ALIAS + "x25519_imp";
        final byte[] secret = new byte[32];
        try {
            final X25519PrivateKeyParameters bcPrivate =
                    new X25519PrivateKeyParameters(new SecureRandom());
            bcPrivate.encode(secret, 0);
            final byte[] publicKey = bcPrivate.generatePublicKey().getEncoded();
            final PrivateKey privateKey = KeyFactory.getInstance("XDH").generatePrivate(
                    new PKCS8EncodedKeySpec(concat(X25519_PKCS8_PREFIX, secret)));
            final X509Certificate certificate = certificate(
                    SubjectPublicKeyInfo.getInstance(concat(X25519_SPKI_PREFIX, publicKey)),
                    softwareP256().getPrivate());
            final KeyStore keyStore = androidKeyStore();
            keyStore.setEntry(alias, new KeyStore.PrivateKeyEntry(privateKey,
                    new Certificate[] { certificate }),
                    new KeyProtection.Builder(KeyProperties.PURPOSE_AGREE_KEY).build());
            final PrivateKey imported = (PrivateKey) keyStore.getKey(alias, null);
            if (!x25519AgreementMatches(imported, publicKey)) {
                return Where.UNAVAILABLE;
            }
            return where(imported, false);
        } catch (Exception | Error e) {
            return Where.UNAVAILABLE;
        } finally {
            Arrays.fill(secret, (byte) 0);
            delete(alias);
        }
    }

    // Checks against software

    private static boolean p256AgreementMatches(final PrivateKey keystorePrivate,
            final PublicKey keystorePublic) throws Exception {
        final KeyPair peer = softwareP256();
        final KeyAgreement inChip = KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE);
        inChip.init(keystorePrivate);
        inChip.doPhase(peer.getPublic(), true);
        final KeyAgreement inSoftware = KeyAgreement.getInstance("ECDH");
        inSoftware.init(peer.getPrivate());
        inSoftware.doPhase(keystorePublic, true);
        return Arrays.equals(inChip.generateSecret(), inSoftware.generateSecret());
    }

    private static boolean x25519AgreementMatches(final PrivateKey keystorePrivate,
            final byte[] keystorePublic) throws Exception {
        final X25519PrivateKeyParameters peer = new X25519PrivateKeyParameters(new SecureRandom());
        final PublicKey peerPublic = KeyFactory.getInstance("XDH").generatePublic(
                new X509EncodedKeySpec(concat(X25519_SPKI_PREFIX,
                        peer.generatePublicKey().getEncoded())));
        final KeyAgreement inChip = KeyAgreement.getInstance("XDH", ANDROID_KEYSTORE);
        inChip.init(keystorePrivate);
        inChip.doPhase(peerPublic, true);
        final X25519Agreement inSoftware = new X25519Agreement();
        inSoftware.init(peer);
        final byte[] expected = new byte[inSoftware.getAgreementSize()];
        inSoftware.calculateAgreement(new X25519PublicKeyParameters(keystorePublic, 0), expected,
                0);
        return Arrays.equals(inChip.generateSecret(), expected);
    }

    // Helpers

    private static Where where(final Key key, final boolean requestedStrongBox)
            throws Exception {
        final KeyInfo info;
        if (key instanceof SecretKey) {
            info = (KeyInfo) SecretKeyFactory.getInstance(key.getAlgorithm(), ANDROID_KEYSTORE)
                    .getKeySpec((SecretKey) key, KeyInfo.class);
        } else {
            info = KeyFactory.getInstance(key.getAlgorithm(), ANDROID_KEYSTORE)
                    .getKeySpec(key, KeyInfo.class);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            switch (info.getSecurityLevel()) {
                case KeyProperties.SECURITY_LEVEL_STRONGBOX:
                    return Where.STRONGBOX;
                case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                    return Where.TEE;
                case KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE:
                    return Where.SECURE_HARDWARE;
                default:
                    return Where.SOFTWARE;
            }
        }
        @SuppressWarnings("deprecation")
        final boolean inside = info.isInsideSecureHardware();
        if (!inside) {
            return Where.SOFTWARE;
        }
        return requestedStrongBox ? Where.STRONGBOX : Where.SECURE_HARDWARE;
    }

    private static KeyPair softwareP256() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    /**
     * The Keystore only imports a private key together with an X.509 certificate. It is just a
     * container here, so a throwaway one is enough.
     */
    private static X509Certificate certificate(final SubjectPublicKeyInfo publicKey,
            final PrivateKey signer) throws Exception {
        final long now = System.currentTimeMillis();
        final X500Name name = new X500Name("CN=cifra-probe");
        final AlgorithmIdentifier signatureAlgorithm =
                new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
        final V3TBSCertificateGenerator tbs = new V3TBSCertificateGenerator();
        tbs.setSerialNumber(new ASN1Integer(1));
        tbs.setIssuer(name);
        tbs.setSubject(name);
        tbs.setStartDate(new Time(new Date(now - 60_000)));
        tbs.setEndDate(new Time(new Date(now + 3_600_000)));
        tbs.setSignature(signatureAlgorithm);
        tbs.setSubjectPublicKeyInfo(publicKey);
        final TBSCertificate tbsCertificate = tbs.generateTBSCertificate();
        final Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(signer);
        signature.update(tbsCertificate.getEncoded(ASN1Encoding.DER));
        final ASN1EncodableVector certificate = new ASN1EncodableVector();
        certificate.add(tbsCertificate);
        certificate.add(signatureAlgorithm);
        certificate.add(new DERBitString(signature.sign()));
        final byte[] der = new DERSequence(certificate).getEncoded(ASN1Encoding.DER);
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    }

    private static KeyStore androidKeyStore() throws Exception {
        final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        return keyStore;
    }

    private static void delete(final String alias) {
        try {
            androidKeyStore().deleteEntry(alias);
        } catch (Exception ignored) {
            // Best effort: probe keys are tiny and useless without the app.
        }
    }

    private static byte[] concat(final byte[] a, final byte[] b) {
        final byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    // Storage

    @Override
    public String toString() {
        return mKeyMintVersion + ";" + mStrongBoxVersion + ";" + mStrongBoxFeature + ";"
                + mAesTee + ";" + mAesStrongBox + ";" + mX25519Generated + ";" + mX25519Imported
                + ";" + mP256GeneratedTee + ";" + mP256ImportedTee + ";" + mP256GeneratedStrongBox
                + ";" + mP256ImportedStrongBox;
    }

    private static KeystoreCapabilities fromString(final String value) {
        if (value == null) {
            return null;
        }
        final String[] parts = value.split(";");
        if (parts.length != 11) {
            return null;
        }
        try {
            final KeystoreCapabilities caps = new KeystoreCapabilities();
            caps.mKeyMintVersion = Integer.parseInt(parts[0]);
            caps.mStrongBoxVersion = Integer.parseInt(parts[1]);
            caps.mStrongBoxFeature = Boolean.parseBoolean(parts[2]);
            caps.mAesTee = Where.valueOf(parts[3]);
            caps.mAesStrongBox = Where.valueOf(parts[4]);
            caps.mX25519Generated = Where.valueOf(parts[5]);
            caps.mX25519Imported = Where.valueOf(parts[6]);
            caps.mP256GeneratedTee = Where.valueOf(parts[7]);
            caps.mP256ImportedTee = Where.valueOf(parts[8]);
            caps.mP256GeneratedStrongBox = Where.valueOf(parts[9]);
            caps.mP256ImportedStrongBox = Where.valueOf(parts[10]);
            return caps;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
