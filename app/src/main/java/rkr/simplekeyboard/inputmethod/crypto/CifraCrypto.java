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

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Message format v1.
 *
 * Keys: X25519. An identity key pair is derived from the BIP39 seed with
 * HPKE DeriveKeyPair(HMAC-SHA512("cifra/identity/v1", seed)).
 *
 * Messages: HPKE (RFC 9180) in Auth mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
 * ChaCha20-Poly1305. Auth mode proves to the recipient that the sender holds the private key of
 * one of their contacts, without a signature that could be shown to third parties.
 *
 * Wire format: "CF" 0x01 | enc (32 bytes) | ciphertext. The header is the AEAD associated data.
 * The plaintext is length-prefixed and zero-padded to a multiple of {@link #PADDING_BLOCK} bytes.
 * No key identifier is sent: the recipient tries their contacts, so a ciphertext does not reveal
 * who wrote it or who can read it.
 */
public final class CifraCrypto {
    public static final String PUBLIC_KEY_HRP = "cifra";
    public static final int KEY_LENGTH = 32;
    public static final int MAX_PLAINTEXT_BYTES = 64 * 1024;
    static final int PADDING_BLOCK = 256;

    private static final byte[] HEADER = { 'C', 'F', 1 };
    private static final byte[] INFO = "cifra/msg/v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IDENTITY_KEY = "cifra/identity/v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] FINGERPRINT_PREFIX =
            "cifra/fingerprint/v1".getBytes(StandardCharsets.UTF_8);
    private static final int ENC_LENGTH = 32;

    public static final String ARMOR_BEGIN = "-----BEGIN CIFRA MESSAGE-----";
    public static final String ARMOR_END = "-----END CIFRA MESSAGE-----";
    private static final Pattern ARMOR_PATTERN = Pattern.compile(
            Pattern.quote(ARMOR_BEGIN) + "(.*?)" + Pattern.quote(ARMOR_END), Pattern.DOTALL);
    private static final Pattern PUBLIC_KEY_PATTERN = Pattern.compile(
            "(?i)\\b" + PUBLIC_KEY_HRP + "1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}\\b");
    private static final int ARMOR_LINE_LENGTH = 64;

    private static final SecureRandom sRandom = new SecureRandom();

    private CifraCrypto() {
        // This utility class is not publicly instantiable.
    }

    public static final class KeyPair {
        public final byte[] mPublicKey;
        public final byte[] mSecretKey;

        KeyPair(final byte[] publicKey, final byte[] secretKey) {
            mPublicKey = publicKey;
            mSecretKey = secretKey;
        }

        public void wipe() {
            Arrays.fill(mSecretKey, (byte) 0);
        }

        /** A copy that a background task can wipe without touching the session's keys. */
        public KeyPair copy() {
            return new KeyPair(mPublicKey.clone(), mSecretKey.clone());
        }
    }

    private static HPKE newHpke() {
        return new HPKE(HPKE.mode_auth, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256,
                HPKE.aead_CHACHA20_POLY1305);
    }

    public static KeyPair deriveKeyPair(final byte[] bip39Seed) {
        final HMac hmac = new HMac(new SHA512Digest());
        hmac.init(new KeyParameter(IDENTITY_KEY));
        hmac.update(bip39Seed, 0, bip39Seed.length);
        final byte[] ikm = new byte[hmac.getMacSize()];
        hmac.doFinal(ikm, 0);
        try {
            final HPKE hpke = newHpke();
            final AsymmetricCipherKeyPair pair = hpke.deriveKeyPair(ikm);
            return new KeyPair(hpke.serializePublicKey(pair.getPublic()),
                    hpke.serializePrivateKey(pair.getPrivate()));
        } finally {
            Arrays.fill(ikm, (byte) 0);
        }
    }

    public static byte[] seal(final String plaintext, final byte[] recipientPublicKey,
            final KeyPair sender) throws InvalidCipherTextException {
        final byte[] padded = pad(plaintext.getBytes(StandardCharsets.UTF_8));
        try {
            final HPKE hpke = newHpke();
            final byte[][] sealed = hpke.seal(hpke.deserializePublicKey(recipientPublicKey), INFO,
                    HEADER, padded, null, null,
                    hpke.deserializePrivateKey(sender.mSecretKey, sender.mPublicKey));
            final byte[] ciphertext = sealed[0];
            final byte[] enc = sealed[1];
            final byte[] wire = new byte[HEADER.length + enc.length + ciphertext.length];
            System.arraycopy(HEADER, 0, wire, 0, HEADER.length);
            System.arraycopy(enc, 0, wire, HEADER.length, enc.length);
            System.arraycopy(ciphertext, 0, wire, HEADER.length + enc.length, ciphertext.length);
            return wire;
        } finally {
            Arrays.fill(padded, (byte) 0);
        }
    }

    /**
     * @return the plaintext, or null if this recipient key and sender key do not open the
     * message.
     */
    public static String open(final byte[] wire, final KeyPair recipient,
            final byte[] senderPublicKey) {
        if (!hasValidHeader(wire)) {
            return null;
        }
        final byte[] enc = Arrays.copyOfRange(wire, HEADER.length, HEADER.length + ENC_LENGTH);
        final byte[] ciphertext = Arrays.copyOfRange(wire, HEADER.length + ENC_LENGTH,
                wire.length);
        byte[] padded = null;
        try {
            final HPKE hpke = newHpke();
            padded = hpke.open(enc,
                    hpke.deserializePrivateKey(recipient.mSecretKey, recipient.mPublicKey),
                    INFO, HEADER, ciphertext, null, null,
                    hpke.deserializePublicKey(senderPublicKey));
            final byte[] message = unpad(padded);
            if (message == null) {
                return null;
            }
            try {
                return new String(message, StandardCharsets.UTF_8);
            } finally {
                Arrays.fill(message, (byte) 0);
            }
        } catch (InvalidCipherTextException | IllegalArgumentException | IllegalStateException e) {
            return null;
        } finally {
            if (padded != null) {
                Arrays.fill(padded, (byte) 0);
            }
        }
    }

    public static boolean hasValidHeader(final byte[] wire) {
        if (wire == null || wire.length < HEADER.length + ENC_LENGTH + 16) {
            return false;
        }
        for (int i = 0; i < HEADER.length; i++) {
            if (wire[i] != HEADER[i]) {
                return false;
            }
        }
        return true;
    }

    static byte[] pad(final byte[] message) {
        if (message.length > MAX_PLAINTEXT_BYTES) {
            throw new IllegalArgumentException("Message too long");
        }
        final int framed = 4 + message.length;
        final int size = ((framed + PADDING_BLOCK - 1) / PADDING_BLOCK) * PADDING_BLOCK;
        final byte[] out = new byte[size];
        out[0] = (byte) (message.length >>> 24);
        out[1] = (byte) (message.length >>> 16);
        out[2] = (byte) (message.length >>> 8);
        out[3] = (byte) message.length;
        System.arraycopy(message, 0, out, 4, message.length);
        Arrays.fill(message, (byte) 0);
        return out;
    }

    static byte[] unpad(final byte[] padded) {
        if (padded.length < 4) {
            return null;
        }
        final int length = ((padded[0] & 0xff) << 24) | ((padded[1] & 0xff) << 16)
                | ((padded[2] & 0xff) << 8) | (padded[3] & 0xff);
        if (length < 0 || length > padded.length - 4) {
            return null;
        }
        return Arrays.copyOfRange(padded, 4, 4 + length);
    }

    public static String armor(final byte[] wire) {
        final String body = Base64.toBase64String(wire);
        final StringBuilder sb = new StringBuilder(body.length() + 80);
        sb.append(ARMOR_BEGIN).append('\n');
        for (int i = 0; i < body.length(); i += ARMOR_LINE_LENGTH) {
            sb.append(body, i, Math.min(body.length(), i + ARMOR_LINE_LENGTH)).append('\n');
        }
        sb.append(ARMOR_END);
        return sb.toString();
    }

    public static boolean containsArmoredMessage(final CharSequence text) {
        return text != null && ARMOR_PATTERN.matcher(text).find();
    }

    /**
     * Finds the first armored message in a text, tolerating the line breaks, spaces and
     * quoting characters that e-mail and chat apps tend to add.
     *
     * @return the wire bytes or null.
     */
    public static byte[] dearmor(final CharSequence text) {
        if (text == null) {
            return null;
        }
        final Matcher matcher = ARMOR_PATTERN.matcher(text);
        if (!matcher.find()) {
            return null;
        }
        final String body = matcher.group(1).replaceAll("[^A-Za-z0-9+/=]", "");
        try {
            final byte[] wire = Base64.decode(body);
            return hasValidHeader(wire) || Ratchet.isRatchetMessage(wire) ? wire : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    public static String encodePublicKey(final byte[] publicKey) {
        return Bech32.encode(PUBLIC_KEY_HRP, publicKey);
    }

    /**
     * Finds a public key ("cifra1...") anywhere in a text, so a whole shared message can be
     * pasted.
     *
     * @return the key bytes, or null if there is no valid key.
     */
    public static byte[] findPublicKey(final CharSequence text) {
        if (text == null) {
            return null;
        }
        final Matcher matcher = PUBLIC_KEY_PATTERN.matcher(text);
        while (matcher.find()) {
            final byte[] key = Bech32.decode(PUBLIC_KEY_HRP, matcher.group());
            if (key != null && isUsablePublicKey(key)) {
                return key;
            }
        }
        return null;
    }

    /**
     * Rejects keys of the wrong size and the low order points that would make the shared
     * secret predictable.
     */
    public static boolean isUsablePublicKey(final byte[] publicKey) {
        if (publicKey == null || publicKey.length != KEY_LENGTH) {
            return false;
        }
        try {
            final X25519KeyPairGenerator generator = new X25519KeyPairGenerator();
            generator.init(new X25519KeyGenerationParameters(sRandom));
            final AsymmetricCipherKeyPair probe = generator.generateKeyPair();
            final X25519Agreement agreement = new X25519Agreement();
            agreement.init(probe.getPrivate());
            final byte[] shared = new byte[agreement.getAgreementSize()];
            agreement.calculateAgreement(new X25519PublicKeyParameters(publicKey, 0), shared, 0);
            Arrays.fill(shared, (byte) 0);
            return true;
        } catch (IllegalStateException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * A short, language independent fingerprint to compare keys aloud or side by side:
     * six groups of five digits (about 99 bits), in the style of Signal safety numbers.
     */
    public static String fingerprint(final byte[] publicKey) {
        final SHA256Digest digest = new SHA256Digest();
        digest.update(FINGERPRINT_PREFIX, 0, FINGERPRINT_PREFIX.length);
        digest.update(publicKey, 0, publicKey.length);
        final byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        final StringBuilder sb = new StringBuilder();
        for (int group = 0; group < 6; group++) {
            long value = 0;
            for (int i = 0; i < 5; i++) {
                value = (value << 8) | (hash[group * 5 + i] & 0xff);
            }
            if (group > 0) {
                sb.append(' ');
            }
            sb.append(String.format(Locale.ROOT, "%05d", value % 100000));
        }
        return sb.toString();
    }
}
