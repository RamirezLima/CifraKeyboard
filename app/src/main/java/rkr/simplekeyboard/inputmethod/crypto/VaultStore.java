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
import java.util.Arrays;
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
 * secret key with a second Keystore key. Raw secret keys only exist in memory while a message is
 * being encrypted or decrypted, and are wiped right after.
 *
 * The BIP39 words and passphrase are never stored: they are the user's backup.
 */
public final class VaultStore {
    private static final String TAG = VaultStore.class.getSimpleName();

    private static final String FILE_NAME = "cifra_vault.bin";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ALIAS_VAULT = "cifra_vault_v1";
    private static final String ALIAS_SECRETS = "cifra_secrets_v1";
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
            final byte[] wrapped = keystoreEncrypt(ALIAS_SECRETS, pair.mSecretKey,
                    pair.mPublicKey);
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
        } catch (GeneralSecurityException | IOException e) {
            Log.e(TAG, "Could not delete Keystore keys", e);
        }
        getFile().delete();
        mVault = new Vault();
    }

    public String encrypt(final String plaintext, final Vault.Contact recipient,
            final Vault.Identity sender) throws VaultException {
        final CifraCrypto.KeyPair senderKeys = unwrap(sender);
        try {
            return CifraCrypto.armor(CifraCrypto.seal(plaintext, recipient.mPublicKey,
                    senderKeys));
        } catch (CryptoException | IllegalArgumentException | IllegalStateException e) {
            throw new VaultException(VaultException.Reason.FAILED, e);
        } finally {
            senderKeys.wipe();
        }
    }

    /**
     * Opens a message with the private key of the given identity, trying every contact (and the
     * own identities, for notes to self) as the sender.
     *
     * @return the result, or null if this identity cannot open the message.
     */
    public DecryptResult decrypt(final byte[] wire, final Vault.Identity recipient)
            throws VaultException {
        final Vault vault = getVault();
        final CifraCrypto.KeyPair recipientKeys = unwrap(recipient);
        try {
            for (final Vault.Contact contact : vault.getContacts()) {
                final String plaintext = CifraCrypto.open(wire, recipientKeys,
                        contact.mPublicKey);
                if (plaintext != null) {
                    return new DecryptResult(plaintext, recipient, contact, null);
                }
            }
            for (final Vault.Identity identity : vault.getIdentities()) {
                final String plaintext = CifraCrypto.open(wire, recipientKeys,
                        identity.mPublicKey);
                if (plaintext != null) {
                    return new DecryptResult(plaintext, recipient, null, identity);
                }
            }
            return null;
        } finally {
            recipientKeys.wipe();
        }
    }

    private CifraCrypto.KeyPair unwrap(final Vault.Identity identity) throws VaultException {
        final byte[] secret = keystoreDecrypt(ALIAS_SECRETS, identity.mWrappedSecretKey,
                identity.mPublicKey);
        return new CifraCrypto.KeyPair(identity.mPublicKey.clone(), secret);
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
            return new VaultException(VaultException.Reason.DEVICE_LOCKED, e);
        }
        return new VaultException(VaultException.Reason.FAILED, e);
    }
}
