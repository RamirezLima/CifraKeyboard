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

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.UserManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;
import android.util.Log;

import org.bouncycastle.crypto.CryptoException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.ProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * The key ring. Persists the {@link Vault} encrypted with a non-exportable AES-256-GCM key that
 * lives in the Android Keystore (in StrongBox when the device has one), and wraps every identity
 * secret key with a second Keystore key that only works for {@link #AUTH_WINDOW_SECONDS} after
 * the user authenticated with the screen lock or a strong biometric. Unwrapped secret keys live
 * in memory only for one secure session.
 *
 * The BIP39 words and passphrase are never stored: they are the user's backup.
 */
public final class VaultStore {
    private static final String TAG = VaultStore.class.getSimpleName();

    private static final String FILE_NAME = "cifra_vault.bin";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ALIAS_VAULT = "cifra_vault_v1";
    /** Wraps the identity secret keys; usable only right after the user authenticated. */
    private static final String ALIAS_SECRETS = "cifra_secrets_v2";
    /** The first secrets key, not bound to authentication. Migrated away on first unlock. */
    private static final String ALIAS_SECRETS_V1 = "cifra_secrets_v1";
    private static final byte WRAP_VERSION_2 = 2;
    /** How long the secrets key stays usable after a successful authentication. */
    public static final int AUTH_WINDOW_SECONDS = 15;
    private static final byte[] VAULT_AAD = "cifra/vault/v1".getBytes(StandardCharsets.UTF_8);
    private static final int GCM_TAG_BITS = 128;

    private static VaultStore sInstance;
    private static final ExecutorService sExecutor = Executors.newSingleThreadExecutor();
    private static final Handler sMainHandler = new Handler(Looper.getMainLooper());

    private final Context mContext;
    private Vault mVault;

    public static synchronized VaultStore getInstance(final Context context) {
        if (sInstance == null) {
            sInstance = new VaultStore(context.getApplicationContext());
        }
        return sInstance;
    }

    private VaultStore(final Context context) {
        // Credential encrypted storage: unreadable until the user unlocks the device once.
        mContext = context;
    }

    public static final class VaultException extends Exception {
        public enum Reason {
            /** The device has not been unlocked since boot, or is locked now. */
            DEVICE_LOCKED,
            /** The Keystore key is gone or was invalidated: restore identities from the words. */
            KEY_LOST,
            /** The secrets key needs a fresh authentication. */
            AUTH_REQUIRED,
            /** The device has no PIN, pattern or password, so keys cannot require one. */
            NO_LOCK_SCREEN,
            DUPLICATE,
            FAILED,
        }

        public final Reason mReason;

        VaultException(final Reason reason, final Throwable cause) {
            super(reason.name(), cause);
            mReason = reason;
        }
    }

    public static final class DecryptResult {
        public final String mPlaintext;
        public final Vault.Identity mRecipient;
        /** The contact that wrote the message, or null when it was one of the own identities. */
        public final Vault.Contact mSenderContact;
        public final Vault.Identity mSenderIdentity;

        DecryptResult(final String plaintext, final Vault.Identity recipient,
                final Vault.Contact senderContact, final Vault.Identity senderIdentity) {
            mPlaintext = plaintext;
            mRecipient = recipient;
            mSenderContact = senderContact;
            mSenderIdentity = senderIdentity;
        }
    }

    /** Result of encrypting with the ratchet. */
    public static final class SendResult {
        public final String mArmored;
        /** The contact has not answered yet: this message relies on identity keys only. */
        public final boolean mFirstChain;

        SendResult(final String armored, final boolean firstChain) {
            mArmored = armored;
            mFirstChain = firstChain;
        }
    }

    /** Result of reading a message in either format. */
    public static final class ReadResult {
        public enum Status { OK, NOT_MINE, ALREADY_READ, TOO_FAR }

        public final Status mStatus;
        public final DecryptResult mMessage;
        public final boolean mRatchet;
        /** Sent before the contact's first answer: protected by identity keys only. */
        public final boolean mFirstChain;
        /** Opened again within the read-again window. */
        public final boolean mReread;
        /** The contact started a new conversation, e.g. from a new phone. */
        public final boolean mRestarted;

        ReadResult(final Status status, final DecryptResult message, final boolean ratchet,
                final boolean firstChain, final boolean reread, final boolean restarted) {
            mStatus = status;
            mMessage = message;
            mRatchet = ratchet;
            mFirstChain = firstChain;
            mReread = reread;
            mRestarted = restarted;
        }

        static ReadResult of(final Status status) {
            return new ReadResult(status, null, false, false, false, false);
        }
    }

    public interface Callback<T> {
        void onResult(T result, VaultException error);
    }

    public interface Task<T> {
        T run() throws VaultException;
    }

    /**
     * Runs key derivation and Keystore operations off the UI thread and delivers the result on
     * the main thread.
     */
    public static <T> void runAsync(final Task<T> task, final Callback<T> callback) {
        sExecutor.execute(() -> {
            T result = null;
            VaultException error = null;
            try {
                result = task.run();
            } catch (VaultException e) {
                error = e;
            } catch (RuntimeException e) {
                Log.e(TAG, "Crypto task failed", e);
                error = new VaultException(VaultException.Reason.FAILED, e);
            }
            final T finalResult = result;
            final VaultException finalError = error;
            sMainHandler.post(() -> callback.onResult(finalResult, finalError));
        });
    }

    public boolean isDeviceSecure() {
        final KeyguardManager keyguard = mContext.getSystemService(KeyguardManager.class);
        return keyguard != null && keyguard.isDeviceSecure();
    }

    public boolean isStorageAvailable() {
        final UserManager userManager = mContext.getSystemService(UserManager.class);
        return userManager == null || userManager.isUserUnlocked();
    }

    public synchronized Vault getVault() throws VaultException {
        if (!isStorageAvailable()) {
            throw new VaultException(VaultException.Reason.DEVICE_LOCKED, null);
        }
        if (mVault == null) {
            mVault = load();
        }
        return mVault;
    }

    private AtomicFile getFile() {
        return new AtomicFile(new File(mContext.getFilesDir(), FILE_NAME));
    }

    private Vault load() throws VaultException {
        final byte[] sealed;
        try {
            sealed = getFile().readFully();
        } catch (FileNotFoundException e) {
            return new Vault();
        } catch (IOException e) {
            throw new VaultException(VaultException.Reason.FAILED, e);
        }
        final byte[] plain = keystoreDecrypt(ALIAS_VAULT, sealed, VAULT_AAD);
        try {
            return Vault.deserialize(plain);
        } catch (IOException e) {
            throw new VaultException(VaultException.Reason.FAILED, e);
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    private void persist(final Vault vault) throws VaultException {
        final byte[] plain = vault.serialize();
        final byte[] sealed;
        try {
            sealed = keystoreEncrypt(ALIAS_VAULT, plain, VAULT_AAD);
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
        final AtomicFile file = getFile();
        FileOutputStream out = null;
        try {
            out = file.startWrite();
            out.write(sealed);
            file.finishWrite(out);
        } catch (IOException e) {
            if (out != null) {
                file.failWrite(out);
            }
            throw new VaultException(VaultException.Reason.FAILED, e);
        }
        mVault = vault;
    }

    /**
     * Derives an identity from BIP39 words (already validated) and an optional passphrase.
     * Different passphrases give unrelated identities from the same words.
     */
    public synchronized Vault.Identity createIdentity(final String name, final String[] words,
            final CharSequence passphrase) throws VaultException {
        final Vault vault = getVault();
        final byte[] seed = Bip39.toSeed(words, passphrase);
        final CifraCrypto.KeyPair pair = CifraCrypto.deriveKeyPair(seed);
        Arrays.fill(seed, (byte) 0);
        try {
            if (vault.findIdentityByPublicKey(pair.mPublicKey) != null) {
                throw new VaultException(VaultException.Reason.DUPLICATE, null);
            }
            final byte[] wrapped = wrapSecret(pair.mSecretKey, pair.mPublicKey);
            final Vault.Identity identity = new Vault.Identity(UUID.randomUUID().toString(), name,
                    pair.mPublicKey.clone(), wrapped, System.currentTimeMillis());
            vault.addIdentity(identity);
            persist(vault);
            return identity;
        } finally {
            pair.wipe();
        }
    }

    public synchronized Vault.Contact addContact(final String name, final byte[] publicKey)
            throws VaultException {
        final Vault vault = getVault();
        if (vault.findContactByPublicKey(publicKey) != null
                || vault.findIdentityByPublicKey(publicKey) != null) {
            throw new VaultException(VaultException.Reason.DUPLICATE, null);
        }
        final Vault.Contact contact = new Vault.Contact(UUID.randomUUID().toString(), name,
                publicKey.clone(), false, System.currentTimeMillis());
        vault.addContact(contact);
        persist(vault);
        return contact;
    }

    public synchronized void setContactVerified(final String contactId, final boolean verified)
            throws VaultException {
        final Vault vault = getVault();
        final Vault.Contact contact = vault.findContact(contactId);
        if (contact != null) {
            vault.replaceContact(new Vault.Contact(contact.mId, contact.mName,
                    contact.mPublicKey, verified, contact.mCreatedAt));
            persist(vault);
        }
    }

    public synchronized void renameContact(final String contactId, final String name)
            throws VaultException {
        final Vault vault = getVault();
        final Vault.Contact contact = vault.findContact(contactId);
        if (contact != null) {
            vault.replaceContact(new Vault.Contact(contact.mId, name, contact.mPublicKey,
                    contact.mVerified, contact.mCreatedAt));
            persist(vault);
        }
    }

    public synchronized void renameIdentity(final String identityId, final String name)
            throws VaultException {
        final Vault vault = getVault();
        final Vault.Identity identity = vault.findIdentity(identityId);
        if (identity != null) {
            vault.replaceIdentity(new Vault.Identity(identity.mId, name, identity.mPublicKey,
                    identity.mWrappedSecretKey, identity.mCreatedAt));
            persist(vault);
        }
    }

    public synchronized void removeContact(final String contactId) throws VaultException {
        final Vault vault = getVault();
        if (vault.removeContact(contactId)) {
            persist(vault);
        }
    }

    public synchronized void removeIdentity(final String identityId) throws VaultException {
        final Vault vault = getVault();
        if (vault.removeIdentity(identityId)) {
            persist(vault);
        }
    }

    public synchronized void setDefaultIdentity(final String identityId) throws VaultException {
        final Vault vault = getVault();
        vault.setDefaultIdentityId(identityId);
        persist(vault);
    }

    /**
     * Deletes the vault and both Keystore keys. Without the keys a copy of the file is useless.
     */
    public synchronized void wipeEverything() {
        try {
            final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            keyStore.deleteEntry(ALIAS_VAULT);
            keyStore.deleteEntry(ALIAS_SECRETS);
            keyStore.deleteEntry(ALIAS_SECRETS_V1);
        } catch (GeneralSecurityException | IOException e) {
            Log.e(TAG, "Could not delete Keystore keys", e);
        }
        getFile().delete();
        mVault = new Vault();
    }

    /**
     * Drops the decrypted vault (names and public keys) from memory. It is read again from disk
     * on the next use.
     */
    public synchronized void clearCache() {
        mVault = null;
    }

    /**
     * Unwraps the secret key of every identity. The Keystore only allows it during
     * {@link #AUTH_WINDOW_SECONDS} after the user authenticated, so call it right after
     * {@link DeviceAuth}. Keys wrapped by the old, unbound key move to the new one here.
     *
     * @return the key pairs by identity id. The caller wipes them when the session ends.
     */
    public synchronized Map<String, CifraCrypto.KeyPair> unlockIdentities()
            throws VaultException {
        final Vault vault = getVault();
        final Map<String, CifraCrypto.KeyPair> keys = new HashMap<>();
        boolean migrated = false;
        try {
            for (final Vault.Identity identity : new ArrayList<>(vault.getIdentities())) {
                final byte[] wrapped = identity.mWrappedSecretKey;
                final byte[] secret;
                if (wrapped.length > 0 && wrapped[0] == WRAP_VERSION_2) {
                    secret = keystoreDecrypt(ALIAS_SECRETS,
                            Arrays.copyOfRange(wrapped, 1, wrapped.length), identity.mPublicKey);
                } else {
                    secret = keystoreDecrypt(ALIAS_SECRETS_V1, wrapped, identity.mPublicKey);
                    vault.replaceIdentity(new Vault.Identity(identity.mId, identity.mName,
                            identity.mPublicKey, wrapSecret(secret, identity.mPublicKey),
                            identity.mCreatedAt));
                    migrated = true;
                }
                keys.put(identity.mId, new CifraCrypto.KeyPair(identity.mPublicKey.clone(),
                        secret));
            }
            if (migrated) {
                persist(vault);
                deleteKey(ALIAS_SECRETS_V1);
            }
            return keys;
        } catch (VaultException e) {
            for (final CifraCrypto.KeyPair pair : keys.values()) {
                pair.wipe();
            }
            throw e;
        }
    }

    public synchronized boolean hasRatchet(final String identityId, final String contactId)
            throws VaultException {
        return !getVault().sessionsFor(identityId, contactId).isEmpty();
    }

    /** Forgets the conversations with this contact: the next message starts a new one. */
    public synchronized void resetRatchet(final String identityId, final String contactId)
            throws VaultException {
        final Vault vault = getVault();
        vault.removeSessions(identityId, contactId);
        persist(vault);
    }

    /**
     * Encrypts with the ratchet, starting a conversation if there is none. The new state is
     * written to disk before the ciphertext is returned, so a message key is never used twice.
     */
    public synchronized SendResult encryptRatchet(final String plaintext,
            final Vault.Contact recipient, final Vault.Identity sender,
            final CifraCrypto.KeyPair senderKeys) throws VaultException {
        final Vault vault = getVault();
        final long now = System.currentTimeMillis();
        final Ratchet.Session stored = vault.activeSession(sender.mId, recipient.mId);
        final Ratchet.Session session = stored != null ? stored.copy()
                : Ratchet.startAsInitiator(senderKeys, sender.mId, recipient.mPublicKey,
                        recipient.mId, now);
        final boolean firstChain = session.isUnanswered();
        final byte[] wire;
        try {
            wire = Ratchet.encrypt(session, plaintext, now);
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new VaultException(VaultException.Reason.FAILED, e);
        }
        vault.putSession(session);
        persist(vault);
        return new SendResult(CifraCrypto.armor(wire), firstChain);
    }

    /**
     * Reads a message in the classic format (any unlocked identity, every contact as a possible
     * sender) or the ratchet format (stored conversations first, then a conversation the
     * contact is starting).
     */
    public synchronized ReadResult read(final byte[] wire,
            final Map<String, CifraCrypto.KeyPair> keys, final long rereadMillis)
            throws VaultException {
        final Vault vault = getVault();
        if (!Ratchet.isRatchetMessage(wire)) {
            for (final Vault.Identity identity : vault.getIdentities()) {
                final CifraCrypto.KeyPair pair = keys.get(identity.mId);
                if (pair == null) {
                    continue;
                }
                final DecryptResult result = decrypt(wire, identity, pair);
                if (result != null) {
                    return new ReadResult(ReadResult.Status.OK, result, false, false, false,
                            false);
                }
            }
            return ReadResult.of(ReadResult.Status.NOT_MINE);
        }
        final long now = System.currentTimeMillis();
        ReadResult.Status failure = ReadResult.Status.NOT_MINE;
        for (final Ratchet.Session session : new ArrayList<>(vault.getSessions())) {
            if (!keys.containsKey(session.mIdentityId)) {
                continue;
            }
            final Ratchet.Result result = Ratchet.decrypt(session, wire, now, rereadMillis);
            if (result.mStatus == Ratchet.Status.OK) {
                vault.putSession(result.mSession);
                persist(vault);
                return ratchetResult(vault, result, false);
            }
            failure = worse(failure, result.mStatus);
        }
        for (final Vault.Identity identity : vault.getIdentities()) {
            final CifraCrypto.KeyPair pair = keys.get(identity.mId);
            if (pair == null) {
                continue;
            }
            for (final Vault.Contact contact : vault.getContacts()) {
                final Ratchet.Result result = Ratchet.tryInitial(pair, identity.mId,
                        contact.mPublicKey, contact.mId, wire, now, rereadMillis);
                if (result.mStatus != Ratchet.Status.OK) {
                    failure = worse(failure, result.mStatus);
                    continue;
                }
                final List<Ratchet.Session> existing = vault.sessionsFor(identity.mId,
                        contact.mId);
                for (final Ratchet.Session session : existing) {
                    if (session.startedWith(result.mSession.getFirstRemoteRatchet())) {
                        // An old first message: it must not replace the conversation.
                        result.mSession.wipe();
                        return ReadResult.of(ReadResult.Status.ALREADY_READ);
                    }
                }
                vault.putSession(result.mSession);
                persist(vault);
                return ratchetResult(vault, result, !existing.isEmpty());
            }
        }
        return ReadResult.of(failure);
    }

    private static ReadResult.Status worse(final ReadResult.Status current,
            final Ratchet.Status status) {
        switch (status) {
            case TOO_FAR:
                return ReadResult.Status.TOO_FAR;
            case ALREADY_READ:
                return current == ReadResult.Status.TOO_FAR ? current
                        : ReadResult.Status.ALREADY_READ;
            default:
                return current;
        }
    }

    private static ReadResult ratchetResult(final Vault vault, final Ratchet.Result result,
            final boolean restarted) {
        final DecryptResult message = new DecryptResult(result.mPlaintext,
                vault.findIdentity(result.mSession.mIdentityId),
                vault.findContact(result.mSession.mContactId), null);
        return new ReadResult(ReadResult.Status.OK, message, true, result.mFirstChain,
                result.mReread, restarted);
    }

    public String encrypt(final String plaintext, final Vault.Contact recipient,
            final CifraCrypto.KeyPair sender) throws VaultException {
        try {
            return CifraCrypto.armor(CifraCrypto.seal(plaintext, recipient.mPublicKey, sender));
        } catch (CryptoException | IllegalArgumentException | IllegalStateException e) {
            throw new VaultException(VaultException.Reason.FAILED, e);
        }
    }

    /**
     * Opens a message with the unlocked key of the given identity, trying every contact (and the
     * own identities, for notes to self) as the sender.
     *
     * @return the result, or null if this identity cannot open the message.
     */
    public DecryptResult decrypt(final byte[] wire, final Vault.Identity recipient,
            final CifraCrypto.KeyPair recipientKeys) throws VaultException {
        final Vault vault = getVault();
        for (final Vault.Contact contact : vault.getContacts()) {
            final String plaintext = CifraCrypto.open(wire, recipientKeys, contact.mPublicKey);
            if (plaintext != null) {
                return new DecryptResult(plaintext, recipient, contact, null);
            }
        }
        for (final Vault.Identity identity : vault.getIdentities()) {
            final String plaintext = CifraCrypto.open(wire, recipientKeys, identity.mPublicKey);
            if (plaintext != null) {
                return new DecryptResult(plaintext, recipient, null, identity);
            }
        }
        return null;
    }

    /**
     * Wraps a secret key with the authentication bound key. Needs a recent authentication.
     */
    private byte[] wrapSecret(final byte[] secret, final byte[] publicKey) throws VaultException {
        if (!isDeviceSecure()) {
            throw new VaultException(VaultException.Reason.NO_LOCK_SCREEN, null);
        }
        final byte[] sealed = keystoreEncrypt(ALIAS_SECRETS, secret, publicKey);
        final byte[] wrapped = new byte[sealed.length + 1];
        wrapped[0] = WRAP_VERSION_2;
        System.arraycopy(sealed, 0, wrapped, 1, sealed.length);
        return wrapped;
    }

    private static void deleteKey(final String alias) {
        try {
            final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            keyStore.deleteEntry(alias);
        } catch (GeneralSecurityException | IOException e) {
            Log.e(TAG, "Could not delete Keystore key", e);
        }
    }

    private static SecretKey getOrCreateKey(final String alias) throws GeneralSecurityException,
            IOException {
        final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        final Key existing = keyStore.getKey(alias, null);
        if (existing instanceof SecretKey) {
            return (SecretKey) existing;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                return generateKey(alias, true, true);
            } catch (GeneralSecurityException | ProviderException e) {
                Log.w(TAG, "StrongBox unavailable, using the TEE", e);
            }
            try {
                return generateKey(alias, false, true);
            } catch (GeneralSecurityException | ProviderException e) {
                Log.w(TAG, "Unlocked device requirement unsupported", e);
            }
        }
        return generateKey(alias, false, false);
    }

    private static SecretKey generateKey(final String alias, final boolean strongBox,
            final boolean unlockedDeviceRequired) throws GeneralSecurityException {
        final KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(strongBox);
            builder.setUnlockedDeviceRequired(unlockedDeviceRequired);
        }
        if (ALIAS_SECRETS.equals(alias)) {
            // The private keys can only be unwrapped shortly after the owner proved who they are.
            builder.setUserAuthenticationRequired(true);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(AUTH_WINDOW_SECONDS,
                        KeyProperties.AUTH_BIOMETRIC_STRONG
                                | KeyProperties.AUTH_DEVICE_CREDENTIAL);
            } else {
                builder.setUserAuthenticationValidityDurationSeconds(AUTH_WINDOW_SECONDS);
            }
        }
        final KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE);
        generator.init(builder.build());
        return generator.generateKey();
    }

    private static byte[] keystoreEncrypt(final String alias, final byte[] plain,
            final byte[] aad) throws VaultException {
        try {
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(alias));
            cipher.updateAAD(aad);
            final byte[] iv = cipher.getIV();
            final byte[] ciphertext = cipher.doFinal(plain);
            final byte[] out = new byte[1 + iv.length + ciphertext.length];
            out[0] = (byte) iv.length;
            System.arraycopy(iv, 0, out, 1, iv.length);
            System.arraycopy(ciphertext, 0, out, 1 + iv.length, ciphertext.length);
            return out;
        } catch (GeneralSecurityException | IOException | ProviderException e) {
            throw keystoreFailure(e);
        }
    }

    private static byte[] keystoreDecrypt(final String alias, final byte[] sealed,
            final byte[] aad) throws VaultException {
        try {
            final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            final Key key = keyStore.getKey(alias, null);
            if (!(key instanceof SecretKey)) {
                throw new VaultException(VaultException.Reason.KEY_LOST, null);
            }
            final int ivLength = sealed[0] & 0xff;
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key,
                    new GCMParameterSpec(GCM_TAG_BITS, sealed, 1, ivLength));
            cipher.updateAAD(aad);
            return cipher.doFinal(sealed, 1 + ivLength, sealed.length - 1 - ivLength);
        } catch (GeneralSecurityException | IOException | ProviderException
                | ArrayIndexOutOfBoundsException e) {
            throw keystoreFailure(e);
        }
    }

    private static VaultException keystoreFailure(final Exception e) {
        Log.e(TAG, "Keystore operation failed", e);
        final String name = e.getClass().getSimpleName();
        if (name.equals("KeyPermanentlyInvalidatedException")
                || name.equals("AEADBadTagException")) {
            return new VaultException(VaultException.Reason.KEY_LOST, e);
        }
        if (name.equals("UserNotAuthenticatedException")) {
            return new VaultException(VaultException.Reason.AUTH_REQUIRED, e);
        }
        return new VaultException(VaultException.Reason.FAILED, e);
    }
}
