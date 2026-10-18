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

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

/**
 * Message format v2: a Double Ratchet with header encryption, following the Signal
 * specification (https://signal.org/docs/specifications/doubleratchet/), adapted to Cifra.
 *
 * <ul>
 * <li>There is no server for prekeys, so a conversation starts from the identity keys: the
 * initiator derives a pair secret from DH(own identity, contact identity) and uses the
 * contact's identity key as the contact's first ratchet key. Messages of this first chain are
 * only protected by the identity keys; every later chain depends on ephemeral keys that are
 * deleted, which gives forward secrecy and recovery after a compromise.</li>
 * <li>Headers (ratchet public key and counters) are encrypted, so a message carries no
 * identifier: the recipient tries the header keys of its conversations.</li>
 * <li>A message key is deleted once used, unless the user chose to be able to read messages
 * again for a while ({@code rereadMillis}).</li>
 * </ul>
 *
 * Wire format: "CF" 0x02 | encrypted header (68 bytes) | encrypted body.
 * Header: nonce (12) | ChaCha20-Poly1305(header key, ratchet public key (32) | PN (4) | N (4)).
 * Body: ChaCha20-Poly1305 with key and nonce from HKDF(message key), associated data = prefix and
 * encrypted header, over the padded text (see {@link CifraCrypto#pad}).
 */
public final class Ratchet {
    static final byte[] PREFIX = { 'C', 'F', 2 };
    private static final int KEY = 32;
    private static final int NONCE = 12;
    private static final int TAG = 16;
    private static final int HEADER_PLAIN = KEY + 4 + 4;
    static final int HEADER_CIPHER = NONCE + HEADER_PLAIN + TAG;
    /** Messages a chain may skip, e.g. lost on the way, before the conversation breaks. */
    static final int MAX_SKIP = 50;
    private static final int MAX_STORED_KEYS = 200;
    private static final int MAX_OLD_HEADER_KEYS = 5;
    /** Keys of messages that did not arrive yet are kept for a week. */
    static final long SKIPPED_KEY_TTL = 7L * 24 * 60 * 60 * 1000;

    private static final byte[] INFO_PAIR = "cifra/v2/pair".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INFO_ROOT = "cifra/v2/root".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INFO_MESSAGE = "cifra/v2/message".getBytes(StandardCharsets.UTF_8);
    private static final int SERIAL_VERSION = 1;

    private static final SecureRandom sRandom = new SecureRandom();

    private Ratchet() {
        // This utility class is not publicly instantiable.
    }

    public static boolean isRatchetMessage(final byte[] wire) {
        return wire != null && wire.length >= PREFIX.length + HEADER_CIPHER + TAG
                && wire[0] == PREFIX[0] && wire[1] == PREFIX[1] && wire[2] == PREFIX[2];
    }

    // State

    public static final class Session {
        public String mId;
        public String mIdentityId;
        public String mContactId;
        public boolean mInitiator;
        byte[] mDhsPrivate;
        byte[] mDhsPublic;
        byte[] mDhr;
        byte[] mRootKey;
        byte[] mSendChain;
        byte[] mReceiveChain;
        byte[] mSendHeader;
        byte[] mReceiveHeader;
        byte[] mNextSendHeader;
        byte[] mNextReceiveHeader;
        /** Header key of the first chain, derived from the identity keys only. */
        byte[] mPairHeader;
        /**
         * For a conversation started by the contact: the contact's first ratchet key. A first
         * message carrying it again is an old message, not a new conversation.
         */
        byte[] mFirstRemoteRatchet;
        int mSent;
        int mReceived;
        int mPreviousSent;
        public long mCreatedAt;
        public long mLastReceivedAt;
        final List<StoredKey> mKeys = new ArrayList<>();
        /** Header keys of past receiving chains, only to tell "already read" from "not mine". */
        final List<byte[]> mOldHeaders = new ArrayList<>();

        /** True until the contact answers: messages sent so far only rely on identity keys. */
        public boolean isUnanswered() {
            return mInitiator && Arrays.equals(mSendHeader, mPairHeader);
        }

        public boolean startedWith(final byte[] remoteRatchetKey) {
            return mFirstRemoteRatchet != null && Arrays.equals(mFirstRemoteRatchet,
                    remoteRatchetKey);
        }

        public byte[] getFirstRemoteRatchet() {
            return mFirstRemoteRatchet == null ? null : mFirstRemoteRatchet.clone();
        }

        Session copy() {
            try {
                return deserialize(serialize());
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        void wipe() {
            for (final byte[] secret : new byte[][] { mDhsPrivate, mRootKey, mSendChain,
                    mReceiveChain, mSendHeader, mReceiveHeader, mNextSendHeader,
                    mNextReceiveHeader, mPairHeader }) {
                if (secret != null) {
                    Arrays.fill(secret, (byte) 0);
                }
            }
            for (final StoredKey key : mKeys) {
                Arrays.fill(key.mMessageKey, (byte) 0);
            }
        }

        public byte[] serialize() {
            final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream out = new DataOutputStream(bytes)) {
                out.writeInt(SERIAL_VERSION);
                out.writeUTF(mId);
                out.writeUTF(mIdentityId);
                out.writeUTF(mContactId);
                out.writeBoolean(mInitiator);
                for (final byte[] value : new byte[][] { mDhsPrivate, mDhsPublic, mDhr, mRootKey,
                        mSendChain, mReceiveChain, mSendHeader, mReceiveHeader, mNextSendHeader,
                        mNextReceiveHeader, mPairHeader, mFirstRemoteRatchet }) {
                    writeOptional(out, value);
                }
                out.writeInt(mSent);
                out.writeInt(mReceived);
                out.writeInt(mPreviousSent);
                out.writeLong(mCreatedAt);
                out.writeLong(mLastReceivedAt);
                out.writeInt(mKeys.size());
                for (final StoredKey key : mKeys) {
                    out.write(key.mHeaderKey);
                    out.writeInt(key.mNumber);
                    out.write(key.mMessageKey);
                    out.writeLong(key.mExpiresAt);
                    out.writeBoolean(key.mRead);
                }
                out.writeInt(mOldHeaders.size());
                for (final byte[] header : mOldHeaders) {
                    out.write(header);
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            return bytes.toByteArray();
        }

        public static Session deserialize(final byte[] data) throws IOException {
            final DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
            if (in.readInt() != SERIAL_VERSION) {
                throw new IOException("Unsupported session version");
            }
            final Session s = new Session();
            s.mId = in.readUTF();
            s.mIdentityId = in.readUTF();
            s.mContactId = in.readUTF();
            s.mInitiator = in.readBoolean();
            s.mDhsPrivate = readOptional(in);
            s.mDhsPublic = readOptional(in);
            s.mDhr = readOptional(in);
            s.mRootKey = readOptional(in);
            s.mSendChain = readOptional(in);
            s.mReceiveChain = readOptional(in);
            s.mSendHeader = readOptional(in);
            s.mReceiveHeader = readOptional(in);
            s.mNextSendHeader = readOptional(in);
            s.mNextReceiveHeader = readOptional(in);
            s.mPairHeader = readOptional(in);
            s.mFirstRemoteRatchet = readOptional(in);
            s.mSent = in.readInt();
            s.mReceived = in.readInt();
            s.mPreviousSent = in.readInt();
            s.mCreatedAt = in.readLong();
            s.mLastReceivedAt = in.readLong();
            final int keys = in.readInt();
            if (keys < 0 || keys > MAX_STORED_KEYS) {
                throw new IOException("Corrupted session");
            }
            for (int i = 0; i < keys; i++) {
                final byte[] headerKey = new byte[KEY];
                in.readFully(headerKey);
                final int number = in.readInt();
                final byte[] messageKey = new byte[KEY];
                in.readFully(messageKey);
                s.mKeys.add(new StoredKey(headerKey, number, messageKey, in.readLong(),
                        in.readBoolean()));
            }
            final int oldHeaders = in.readInt();
            if (oldHeaders < 0 || oldHeaders > MAX_OLD_HEADER_KEYS) {
                throw new IOException("Corrupted session");
            }
            for (int i = 0; i < oldHeaders; i++) {
                final byte[] header = new byte[KEY];
                in.readFully(header);
                s.mOldHeaders.add(header);
            }
            return s;
        }
    }

    static final class StoredKey {
        final byte[] mHeaderKey;
        final int mNumber;
        final byte[] mMessageKey;
        long mExpiresAt;
        /** Already read (kept to read again) rather than skipped (not arrived yet). */
        boolean mRead;

        StoredKey(final byte[] headerKey, final int number, final byte[] messageKey,
                final long expiresAt, final boolean read) {
            mHeaderKey = headerKey;
            mNumber = number;
            mMessageKey = messageKey;
            mExpiresAt = expiresAt;
            mRead = read;
        }
    }

    public enum Status {
        OK,
        /** Not a message of this conversation. */
        NOT_MINE,
        /** A message of this conversation whose key was already burned. */
        ALREADY_READ,
        /** Too many messages were lost in between. */
        TOO_FAR,
    }

    public static final class Result {
        public final Status mStatus;
        public final String mPlaintext;
        /** The updated state to store; the original is left untouched. */
        public final Session mSession;
        /** Sent before the contact's first answer: protected by the identity keys only. */
        public final boolean mFirstChain;
        /** Opened with a key kept for reading again. */
        public final boolean mReread;

        Result(final Status status, final String plaintext, final Session session,
                final boolean firstChain, final boolean reread) {
            mStatus = status;
            mPlaintext = plaintext;
            mSession = session;
            mFirstChain = firstChain;
            mReread = reread;
        }

        static Result of(final Status status) {
            return new Result(status, null, null, false, false);
        }
    }

    // Starting a conversation

    /**
     * Starts a conversation as the initiator. The first ratchet step uses the contact's
     * identity key, which stands in for the prekey a server would provide.
     */
    public static Session startAsInitiator(final CifraCrypto.KeyPair me, final String identityId,
            final byte[] contactPublic, final String contactId, final long now) {
        final byte[][] pair = pairSecrets(me, contactPublic, me.mPublicKey, contactPublic);
        final Session s = new Session();
        s.mId = UUID.randomUUID().toString();
        s.mIdentityId = identityId;
        s.mContactId = contactId;
        s.mInitiator = true;
        s.mCreatedAt = now;
        newRatchetKey(s);
        s.mDhr = contactPublic.clone();
        final byte[][] root = kdfRoot(pair[0], dh(s.mDhsPrivate, s.mDhr));
        s.mRootKey = root[0];
        s.mSendChain = root[1];
        s.mNextSendHeader = root[2];
        s.mSendHeader = pair[1];
        s.mPairHeader = pair[1].clone();
        s.mNextReceiveHeader = pair[2];
        Arrays.fill(pair[0], (byte) 0);
        return s;
    }

    /**
     * Tries to read the first message of a conversation started by the contact.
     *
     * @return the result with a new session, or a result with status NOT_MINE.
     */
    public static Result tryInitial(final CifraCrypto.KeyPair me, final String identityId,
            final byte[] contactPublic, final String contactId, final byte[] wire, final long now,
            final long rereadMillis) {
        if (!isRatchetMessage(wire)) {
            return Result.of(Status.NOT_MINE);
        }
        final byte[][] pair = pairSecrets(me, contactPublic, contactPublic, me.mPublicKey);
        if (decryptHeader(pair[1], wire) == null) {
            return Result.of(Status.NOT_MINE);
        }
        final Session s = new Session();
        s.mId = UUID.randomUUID().toString();
        s.mIdentityId = identityId;
        s.mContactId = contactId;
        s.mInitiator = false;
        s.mCreatedAt = now;
        // The identity key acts as the first ratchet key; it is replaced in the next step.
        s.mDhsPrivate = me.mSecretKey.clone();
        s.mDhsPublic = me.mPublicKey.clone();
        s.mRootKey = pair[0];
        s.mNextSendHeader = pair[2];
        s.mNextReceiveHeader = pair[1];
        s.mPairHeader = pair[1].clone();
        final Result result = decrypt(s, wire, now, rereadMillis);
        if (result.mStatus != Status.OK) {
            s.wipe();
            return result;
        }
        result.mSession.mFirstRemoteRatchet = result.mSession.mDhr.clone();
        s.wipe();
        return result;
    }

    // Sending and receiving

    /**
     * Encrypts one message and advances the state. Store the state before sending the result,
     * so a message key is never used twice.
     */
    public static byte[] encrypt(final Session s, final String plaintext, final long now) {
        final byte[][] step = kdfChain(s.mSendChain);
        Arrays.fill(s.mSendChain, (byte) 0);
        s.mSendChain = step[0];
        final byte[] messageKey = step[1];
        final byte[] header = new byte[HEADER_PLAIN];
        System.arraycopy(s.mDhsPublic, 0, header, 0, KEY);
        putInt(header, KEY, s.mPreviousSent);
        putInt(header, KEY + 4, s.mSent);
        final byte[] encryptedHeader = encryptHeader(s.mSendHeader, header);
        s.mSent++;
        final byte[] padded = CifraCrypto.pad(plaintext.getBytes(StandardCharsets.UTF_8));
        try {
            final byte[] body = encryptBody(messageKey, padded, associatedData(encryptedHeader));
            final byte[] wire = new byte[PREFIX.length + encryptedHeader.length + body.length];
            System.arraycopy(PREFIX, 0, wire, 0, PREFIX.length);
            System.arraycopy(encryptedHeader, 0, wire, PREFIX.length, encryptedHeader.length);
            System.arraycopy(body, 0, wire, PREFIX.length + encryptedHeader.length, body.length);
            return wire;
        } finally {
            Arrays.fill(messageKey, (byte) 0);
            Arrays.fill(padded, (byte) 0);
        }
    }

    /**
     * Tries to read a message with this conversation. Works on a copy: the given state is not
     * changed, the result carries the new one.
     */
    public static Result decrypt(final Session original, final byte[] wire, final long now,
            final long rereadMillis) {
        if (!isRatchetMessage(wire)) {
            return Result.of(Status.NOT_MINE);
        }
        final Session s = original.copy();
        purgeExpired(s, now);
        final byte[] encryptedHeader = Arrays.copyOfRange(wire, PREFIX.length,
                PREFIX.length + HEADER_CIPHER);
        final byte[] body = Arrays.copyOfRange(wire, PREFIX.length + HEADER_CIPHER, wire.length);
        final byte[] ad = associatedData(encryptedHeader);

        // 1. Keys kept for messages that were skipped or that may be read again.
        for (final Iterator<StoredKey> it = s.mKeys.iterator(); it.hasNext(); ) {
            final StoredKey key = it.next();
            final byte[] header = decryptHeader(key.mHeaderKey, wire);
            if (header == null || getInt(header, KEY + 4) != key.mNumber) {
                continue;
            }
            final String text = openBody(key.mMessageKey, body, ad);
            if (text == null) {
                return Result.of(Status.NOT_MINE);
            }
            final boolean reread = key.mRead;
            final boolean firstChain = Arrays.equals(key.mHeaderKey, s.mPairHeader);
            if (!key.mRead) {
                if (rereadMillis > 0) {
                    key.mRead = true;
                    key.mExpiresAt = now + rereadMillis;
                } else {
                    Arrays.fill(key.mMessageKey, (byte) 0);
                    it.remove();
                }
            }
            s.mLastReceivedAt = now;
            return new Result(Status.OK, text, s, firstChain, reread);
        }

        // 2. The current receiving chain, or the next one (the contact turned the ratchet).
        byte[] header = s.mReceiveHeader == null ? null : decryptHeader(s.mReceiveHeader, wire);
        boolean turn = false;
        if (header != null && !Arrays.equals(Arrays.copyOf(header, KEY), s.mDhr)) {
            // Same header key but another ratchet key: a restarted conversation, not this one.
            header = null;
        }
        if (header == null && s.mNextReceiveHeader != null) {
            header = decryptHeader(s.mNextReceiveHeader, wire);
            turn = header != null;
        }
        if (header == null) {
            for (final byte[] old : s.mOldHeaders) {
                if (decryptHeader(old, wire) != null) {
                    return Result.of(Status.ALREADY_READ);
                }
            }
            return Result.of(Status.NOT_MINE);
        }
        final byte[] ratchetKey = Arrays.copyOf(header, KEY);
        final int previous = getInt(header, KEY);
        final int number = getInt(header, KEY + 4);
        if (!turn && number < s.mReceived) {
            return Result.of(Status.ALREADY_READ);
        }
        try {
            if (turn) {
                if (!skipKeys(s, previous, now)) {
                    return Result.of(Status.TOO_FAR);
                }
                turnRatchet(s, ratchetKey);
            }
            if (!skipKeys(s, number, now)) {
                return Result.of(Status.TOO_FAR);
            }
        } catch (IllegalStateException e) {
            // Low order ratchet key: not a valid message.
            return Result.of(Status.NOT_MINE);
        }
        final byte[] receiveHeader = s.mReceiveHeader.clone();
        final byte[][] step = kdfChain(s.mReceiveChain);
        Arrays.fill(s.mReceiveChain, (byte) 0);
        s.mReceiveChain = step[0];
        final byte[] messageKey = step[1];
        s.mReceived++;
        final String text = openBody(messageKey, body, ad);
        if (text == null) {
            Arrays.fill(messageKey, (byte) 0);
            return Result.of(Status.NOT_MINE);
        }
        if (rereadMillis > 0) {
            addKey(s, new StoredKey(receiveHeader, number, messageKey, now + rereadMillis, true));
        } else {
            Arrays.fill(messageKey, (byte) 0);
        }
        s.mLastReceivedAt = now;
        return new Result(Status.OK, text, s, Arrays.equals(receiveHeader, s.mPairHeader), false);
    }

    private static boolean skipKeys(final Session s, final int until, final long now) {
        if (s.mReceived + MAX_SKIP < until) {
            return false;
        }
        if (s.mReceiveChain == null) {
            return true;
        }
        while (s.mReceived < until) {
            final byte[][] step = kdfChain(s.mReceiveChain);
            Arrays.fill(s.mReceiveChain, (byte) 0);
            s.mReceiveChain = step[0];
            addKey(s, new StoredKey(s.mReceiveHeader.clone(), s.mReceived, step[1],
                    now + SKIPPED_KEY_TTL, false));
            s.mReceived++;
        }
        return true;
    }

    private static void turnRatchet(final Session s, final byte[] ratchetKey) {
        if (s.mReceiveHeader != null) {
            s.mOldHeaders.add(0, s.mReceiveHeader.clone());
            while (s.mOldHeaders.size() > MAX_OLD_HEADER_KEYS) {
                s.mOldHeaders.remove(s.mOldHeaders.size() - 1);
            }
        }
        s.mPreviousSent = s.mSent;
        s.mSent = 0;
        s.mReceived = 0;
        s.mSendHeader = s.mNextSendHeader;
        s.mReceiveHeader = s.mNextReceiveHeader;
        s.mDhr = ratchetKey.clone();
        final byte[][] receive = kdfRoot(s.mRootKey, dh(s.mDhsPrivate, s.mDhr));
        s.mRootKey = receive[0];
        s.mReceiveChain = receive[1];
        s.mNextReceiveHeader = receive[2];
        // The previous ratchet key (or the identity key, for the first step) is gone for good.
        Arrays.fill(s.mDhsPrivate, (byte) 0);
        newRatchetKey(s);
        final byte[][] send = kdfRoot(s.mRootKey, dh(s.mDhsPrivate, s.mDhr));
        s.mRootKey = send[0];
        s.mSendChain = send[1];
        s.mNextSendHeader = send[2];
    }

    private static void newRatchetKey(final Session s) {
        final X25519PrivateKeyParameters key = new X25519PrivateKeyParameters(sRandom);
        s.mDhsPrivate = key.getEncoded();
        s.mDhsPublic = key.generatePublicKey().getEncoded();
    }

    private static void addKey(final Session s, final StoredKey key) {
        s.mKeys.add(key);
        while (s.mKeys.size() > MAX_STORED_KEYS) {
            Arrays.fill(s.mKeys.get(0).mMessageKey, (byte) 0);
            s.mKeys.remove(0);
        }
    }

    private static void purgeExpired(final Session s, final long now) {
        for (final Iterator<StoredKey> it = s.mKeys.iterator(); it.hasNext(); ) {
            final StoredKey key = it.next();
            if (key.mExpiresAt <= now) {
                Arrays.fill(key.mMessageKey, (byte) 0);
                it.remove();
            }
        }
    }

    // Primitives

    /**
     * Secrets shared by a pair of identities for the conversation started by {@code initiator}:
     * the first root key, the header key of the initiator's first chain and the header key of
     * the responder's first chain. The order of the public keys keeps the two directions apart.
     */
    private static byte[][] pairSecrets(final CifraCrypto.KeyPair me, final byte[] other,
            final byte[] initiator, final byte[] responder) {
        final byte[] shared = dh(me.mSecretKey, other);
        final byte[] info = new byte[INFO_PAIR.length + 2 * KEY];
        System.arraycopy(INFO_PAIR, 0, info, 0, INFO_PAIR.length);
        System.arraycopy(initiator, 0, info, INFO_PAIR.length, KEY);
        System.arraycopy(responder, 0, info, INFO_PAIR.length + KEY, KEY);
        final byte[] out = hkdf(shared, new byte[KEY], info, 3 * KEY);
        Arrays.fill(shared, (byte) 0);
        return split(out);
    }

    private static byte[][] kdfRoot(final byte[] rootKey, final byte[] dhOutput) {
        final byte[] out = hkdf(dhOutput, rootKey, INFO_ROOT, 3 * KEY);
        Arrays.fill(dhOutput, (byte) 0);
        return split(out);
    }

    /** @return the next chain key and the message key. */
    private static byte[][] kdfChain(final byte[] chainKey) {
        return new byte[][] { hmac(chainKey, (byte) 2), hmac(chainKey, (byte) 1) };
    }

    private static byte[][] split(final byte[] out) {
        final byte[][] parts = new byte[][] { Arrays.copyOfRange(out, 0, KEY),
                Arrays.copyOfRange(out, KEY, 2 * KEY), Arrays.copyOfRange(out, 2 * KEY, 3 * KEY) };
        Arrays.fill(out, (byte) 0);
        return parts;
    }

    private static byte[] dh(final byte[] privateKey, final byte[] publicKey) {
        final X25519Agreement agreement = new X25519Agreement();
        agreement.init(new X25519PrivateKeyParameters(privateKey, 0));
        final byte[] out = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(new X25519PublicKeyParameters(publicKey, 0), out, 0);
        return out;
    }

    private static byte[] hkdf(final byte[] ikm, final byte[] salt, final byte[] info,
            final int length) {
        final HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
        generator.init(new HKDFParameters(ikm, salt, info));
        final byte[] out = new byte[length];
        generator.generateBytes(out, 0, length);
        return out;
    }

    private static byte[] hmac(final byte[] key, final byte input) {
        final HMac mac = new HMac(new SHA256Digest());
        mac.init(new KeyParameter(key));
        mac.update(input);
        final byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    private static byte[] encryptHeader(final byte[] headerKey, final byte[] header) {
        final byte[] nonce = new byte[NONCE];
        sRandom.nextBytes(nonce);
        final byte[] sealed = aead(true, headerKey, nonce, PREFIX, header);
        final byte[] out = new byte[NONCE + sealed.length];
        System.arraycopy(nonce, 0, out, 0, NONCE);
        System.arraycopy(sealed, 0, out, NONCE, sealed.length);
        return out;
    }

    /** @return the header, or null if this header key does not open it. */
    private static byte[] decryptHeader(final byte[] headerKey, final byte[] wire) {
        final byte[] nonce = Arrays.copyOfRange(wire, PREFIX.length, PREFIX.length + NONCE);
        final byte[] sealed = Arrays.copyOfRange(wire, PREFIX.length + NONCE,
                PREFIX.length + HEADER_CIPHER);
        return aead(false, headerKey, nonce, PREFIX, sealed);
    }

    private static byte[] encryptBody(final byte[] messageKey, final byte[] padded,
            final byte[] ad) {
        final byte[] keyAndNonce = hkdf(messageKey, new byte[KEY], INFO_MESSAGE, KEY + NONCE);
        try {
            return aead(true, Arrays.copyOf(keyAndNonce, KEY),
                    Arrays.copyOfRange(keyAndNonce, KEY, KEY + NONCE), ad, padded);
        } finally {
            Arrays.fill(keyAndNonce, (byte) 0);
        }
    }

    private static String openBody(final byte[] messageKey, final byte[] body, final byte[] ad) {
        final byte[] keyAndNonce = hkdf(messageKey, new byte[KEY], INFO_MESSAGE, KEY + NONCE);
        final byte[] padded = aead(false, Arrays.copyOf(keyAndNonce, KEY),
                Arrays.copyOfRange(keyAndNonce, KEY, KEY + NONCE), ad, body);
        Arrays.fill(keyAndNonce, (byte) 0);
        if (padded == null) {
            return null;
        }
        final byte[] message = CifraCrypto.unpad(padded);
        Arrays.fill(padded, (byte) 0);
        if (message == null) {
            return null;
        }
        try {
            return new String(message, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(message, (byte) 0);
        }
    }

    private static byte[] associatedData(final byte[] encryptedHeader) {
        final byte[] ad = new byte[PREFIX.length + encryptedHeader.length];
        System.arraycopy(PREFIX, 0, ad, 0, PREFIX.length);
        System.arraycopy(encryptedHeader, 0, ad, PREFIX.length, encryptedHeader.length);
        return ad;
    }

    /** @return the output, or null when opening fails. */
    private static byte[] aead(final boolean encrypt, final byte[] key, final byte[] nonce,
            final byte[] ad, final byte[] input) {
        final ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
        cipher.init(encrypt, new AEADParameters(new KeyParameter(key), TAG * 8, nonce, ad));
        final byte[] out = new byte[cipher.getOutputSize(input.length)];
        try {
            final int length = cipher.processBytes(input, 0, input.length, out, 0);
            cipher.doFinal(out, length);
            return out;
        } catch (InvalidCipherTextException | IllegalStateException e) {
            if (encrypt) {
                throw new IllegalStateException(e);
            }
            return null;
        }
    }

    private static void putInt(final byte[] out, final int offset, final int value) {
        out[offset] = (byte) (value >>> 24);
        out[offset + 1] = (byte) (value >>> 16);
        out[offset + 2] = (byte) (value >>> 8);
        out[offset + 3] = (byte) value;
    }

    private static int getInt(final byte[] in, final int offset) {
        return ((in[offset] & 0xff) << 24) | ((in[offset + 1] & 0xff) << 16)
                | ((in[offset + 2] & 0xff) << 8) | (in[offset + 3] & 0xff);
    }

    private static void writeOptional(final DataOutputStream out, final byte[] value)
            throws IOException {
        out.writeBoolean(value != null);
        if (value != null) {
            out.writeInt(value.length);
            out.write(value);
        }
    }

    private static byte[] readOptional(final DataInputStream in) throws IOException {
        if (!in.readBoolean()) {
            return null;
        }
        final int length = in.readInt();
        if (length < 0 || length > 64) {
            throw new IOException("Corrupted session");
        }
        final byte[] value = new byte[length];
        in.readFully(value);
        return value;
    }
}
