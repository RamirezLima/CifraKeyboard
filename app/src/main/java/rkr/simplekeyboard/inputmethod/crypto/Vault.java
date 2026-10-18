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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * The user's identities (own key pairs) and contacts (other people's public keys).
 *
 * Secret keys are never held in clear here: {@link Identity#mWrappedSecretKey} is encrypted by a
 * separate Android Keystore key and only unwrapped for the duration of one operation. The
 * serialized vault is itself encrypted before it is written to disk, see {@link VaultStore}.
 */
public final class Vault {
    /** 1: identities and contacts. 2: also ratchet conversations. */
    private static final int FORMAT_VERSION = 2;
    /** Conversations kept per identity and contact, e.g. after the contact changed phones. */
    static final int MAX_SESSIONS_PER_CONTACT = 3;

    public static final class Identity {
        public final String mId;
        public final String mName;
        public final byte[] mPublicKey;
        final byte[] mWrappedSecretKey;
        public final long mCreatedAt;

        Identity(final String id, final String name, final byte[] publicKey,
                final byte[] wrappedSecretKey, final long createdAt) {
            mId = id;
            mName = name;
            mPublicKey = publicKey;
            mWrappedSecretKey = wrappedSecretKey;
            mCreatedAt = createdAt;
        }

        public String getEncodedPublicKey() {
            return CifraCrypto.encodePublicKey(mPublicKey);
        }

        public String getFingerprint() {
            return CifraCrypto.fingerprint(mPublicKey);
        }
    }

    public static final class Contact {
        public final String mId;
        public final String mName;
        public final byte[] mPublicKey;
        public final boolean mVerified;
        public final long mCreatedAt;

        Contact(final String id, final String name, final byte[] publicKey,
                final boolean verified, final long createdAt) {
            mId = id;
            mName = name;
            mPublicKey = publicKey;
            mVerified = verified;
            mCreatedAt = createdAt;
        }

        public String getEncodedPublicKey() {
            return CifraCrypto.encodePublicKey(mPublicKey);
        }

        public String getFingerprint() {
            return CifraCrypto.fingerprint(mPublicKey);
        }
    }

    private final List<Identity> mIdentities = new ArrayList<>();
    private final List<Contact> mContacts = new ArrayList<>();
    private final List<Ratchet.Session> mSessions = new ArrayList<>();
    private String mDefaultIdentityId;

    public List<Identity> getIdentities() {
        return Collections.unmodifiableList(mIdentities);
    }

    public List<Contact> getContacts() {
        return Collections.unmodifiableList(mContacts);
    }

    public List<Ratchet.Session> getSessions() {
        return Collections.unmodifiableList(mSessions);
    }

    public List<Ratchet.Session> sessionsFor(final String identityId, final String contactId) {
        final List<Ratchet.Session> found = new ArrayList<>();
        for (final Ratchet.Session session : mSessions) {
            if (session.mIdentityId.equals(identityId) && session.mContactId.equals(contactId)) {
                found.add(session);
            }
        }
        return found;
    }

    /**
     * @return the conversation to send with: the one that heard from the contact last, or the
     * newest one; null when there is none.
     */
    public Ratchet.Session activeSession(final String identityId, final String contactId) {
        Ratchet.Session best = null;
        for (final Ratchet.Session session : sessionsFor(identityId, contactId)) {
            if (best == null || rank(session) >= rank(best)) {
                best = session;
            }
        }
        return best;
    }

    private static long rank(final Ratchet.Session session) {
        return Math.max(session.mLastReceivedAt, session.mCreatedAt);
    }

    /** Adds the conversation or replaces the stored one with the same id. */
    void putSession(final Ratchet.Session session) {
        for (int i = 0; i < mSessions.size(); i++) {
            if (mSessions.get(i).mId.equals(session.mId)) {
                mSessions.get(i).wipe();
                mSessions.set(i, session);
                return;
            }
        }
        mSessions.add(session);
        final List<Ratchet.Session> same = sessionsFor(session.mIdentityId, session.mContactId);
        while (same.size() > MAX_SESSIONS_PER_CONTACT) {
            Ratchet.Session oldest = same.get(0);
            for (final Ratchet.Session candidate : same) {
                if (rank(candidate) < rank(oldest)) {
                    oldest = candidate;
                }
            }
            same.remove(oldest);
            mSessions.remove(oldest);
            oldest.wipe();
        }
    }

    void removeSessions(final String identityId, final String contactId) {
        for (final Iterator<Ratchet.Session> it = mSessions.iterator(); it.hasNext(); ) {
            final Ratchet.Session session = it.next();
            if ((identityId == null || session.mIdentityId.equals(identityId))
                    && (contactId == null || session.mContactId.equals(contactId))) {
                session.wipe();
                it.remove();
            }
        }
    }

    public Identity findIdentity(final String id) {
        for (final Identity identity : mIdentities) {
            if (identity.mId.equals(id)) {
                return identity;
            }
        }
        return null;
    }

    public Contact findContact(final String id) {
        for (final Contact contact : mContacts) {
            if (contact.mId.equals(id)) {
                return contact;
            }
        }
        return null;
    }

    public Identity findIdentityByPublicKey(final byte[] publicKey) {
        for (final Identity identity : mIdentities) {
            if (Arrays.equals(identity.mPublicKey, publicKey)) {
                return identity;
            }
        }
        return null;
    }

    public Contact findContactByPublicKey(final byte[] publicKey) {
        for (final Contact contact : mContacts) {
            if (Arrays.equals(contact.mPublicKey, publicKey)) {
                return contact;
            }
        }
        return null;
    }

    /**
     * @return the identity used to sign outgoing messages: the one chosen by the user, or the
     * oldest one.
     */
    public Identity getDefaultIdentity() {
        final Identity chosen = mDefaultIdentityId == null ? null
                : findIdentity(mDefaultIdentityId);
        if (chosen != null) {
            return chosen;
        }
        return mIdentities.isEmpty() ? null : mIdentities.get(0);
    }

    void setDefaultIdentityId(final String id) {
        mDefaultIdentityId = id;
    }

    void addIdentity(final Identity identity) {
        mIdentities.add(identity);
    }

    void addContact(final Contact contact) {
        mContacts.add(contact);
    }

    boolean removeIdentity(final String id) {
        final Identity identity = findIdentity(id);
        if (identity == null) {
            return false;
        }
        mIdentities.remove(identity);
        Arrays.fill(identity.mWrappedSecretKey, (byte) 0);
        removeSessions(id, null);
        if (id.equals(mDefaultIdentityId)) {
            mDefaultIdentityId = null;
        }
        return true;
    }

    boolean removeContact(final String id) {
        final Contact contact = findContact(id);
        if (contact == null) {
            return false;
        }
        removeSessions(null, id);
        return mContacts.remove(contact);
    }

    boolean replaceContact(final Contact updated) {
        for (int i = 0; i < mContacts.size(); i++) {
            if (mContacts.get(i).mId.equals(updated.mId)) {
                mContacts.set(i, updated);
                return true;
            }
        }
        return false;
    }

    boolean replaceIdentity(final Identity updated) {
        for (int i = 0; i < mIdentities.size(); i++) {
            if (mIdentities.get(i).mId.equals(updated.mId)) {
                mIdentities.set(i, updated);
                return true;
            }
        }
        return false;
    }

    byte[] serialize() {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(FORMAT_VERSION);
            out.writeBoolean(mDefaultIdentityId != null);
            if (mDefaultIdentityId != null) {
                out.writeUTF(mDefaultIdentityId);
            }
            out.writeInt(mIdentities.size());
            for (final Identity identity : mIdentities) {
                out.writeUTF(identity.mId);
                out.writeUTF(identity.mName);
                writeBytes(out, identity.mPublicKey);
                writeBytes(out, identity.mWrappedSecretKey);
                out.writeLong(identity.mCreatedAt);
            }
            out.writeInt(mContacts.size());
            for (final Contact contact : mContacts) {
                out.writeUTF(contact.mId);
                out.writeUTF(contact.mName);
                writeBytes(out, contact.mPublicKey);
                out.writeBoolean(contact.mVerified);
                out.writeLong(contact.mCreatedAt);
            }
            out.writeInt(mSessions.size());
            for (final Ratchet.Session session : mSessions) {
                final byte[] data = session.serialize();
                out.writeInt(data.length);
                out.write(data);
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return bytes.toByteArray();
    }

    static Vault deserialize(final byte[] data) throws IOException {
        final Vault vault = new Vault();
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(data))) {
            final int version = in.readInt();
            if (version != 1 && version != FORMAT_VERSION) {
                throw new IOException("Unsupported vault version " + version);
            }
            if (in.readBoolean()) {
                vault.mDefaultIdentityId = in.readUTF();
            }
            final int identities = in.readInt();
            for (int i = 0; i < identities; i++) {
                vault.mIdentities.add(new Identity(in.readUTF(), in.readUTF(), readBytes(in),
                        readBytes(in), in.readLong()));
            }
            final int contacts = in.readInt();
            for (int i = 0; i < contacts; i++) {
                vault.mContacts.add(new Contact(in.readUTF(), in.readUTF(), readBytes(in),
                        in.readBoolean(), in.readLong()));
            }
            if (version >= 2) {
                final int sessions = in.readInt();
                for (int i = 0; i < sessions; i++) {
                    final int length = in.readInt();
                    if (length < 0 || length > 256 * 1024) {
                        throw new IOException("Corrupted vault");
                    }
                    final byte[] blob = new byte[length];
                    in.readFully(blob);
                    vault.mSessions.add(Ratchet.Session.deserialize(blob));
                }
            }
        }
        return vault;
    }

    private static void writeBytes(final DataOutputStream out, final byte[] data)
            throws IOException {
        out.writeInt(data.length);
        out.write(data);
    }

    private static byte[] readBytes(final DataInputStream in) throws IOException {
        final int length = in.readInt();
        if (length < 0 || length > 4096) {
            throw new IOException("Corrupted vault");
        }
        final byte[] data = new byte[length];
        in.readFully(data);
        return data;
    }
}
