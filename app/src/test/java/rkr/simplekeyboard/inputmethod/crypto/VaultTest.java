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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;

public class VaultTest {
    private static CifraCrypto.KeyPair keys(final String mnemonic) {
        return CifraCrypto.deriveKeyPair(Bip39.toSeed(Bip39.split(mnemonic), ""));
    }

    private static final CifraCrypto.KeyPair ANA = keys("legal winner thank year wave sausage "
            + "worth useful legal winner thank yellow");
    private static final CifraCrypto.KeyPair BETO = keys("ozone drill grab fiber curtain grace "
            + "pudding thank cruise elder eight picnic");

    private static Vault sample() {
        final Vault vault = new Vault();
        vault.addIdentity(new Vault.Identity("id-ana", "Ana", ANA.mPublicKey, new byte[61], 1));
        vault.addContact(new Vault.Contact("c-beto", "Beto", BETO.mPublicKey, true, 2));
        vault.setDefaultIdentityId("id-ana");
        return vault;
    }

    @Test
    public void roundTripWithConversations() throws Exception {
        final Vault vault = sample();
        final Ratchet.Session session = Ratchet.startAsInitiator(ANA, "id-ana", BETO.mPublicKey,
                "c-beto", 10);
        Ratchet.encrypt(session, "hello", 10);
        vault.putSession(session);
        final Vault copy = Vault.deserialize(vault.serialize());
        assertEquals("Ana", copy.getIdentities().get(0).mName);
        assertEquals("Beto", copy.getContacts().get(0).mName);
        assertEquals(1, copy.getSessions().size());
        assertArrayEquals(session.serialize(), copy.getSessions().get(0).serialize());
        assertEquals("id-ana", copy.getDefaultIdentity().mId);
    }

    @Test
    public void readsTheFirstFormat() throws Exception {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(1);
            out.writeBoolean(false);
            out.writeInt(1);
            out.writeUTF("id-ana");
            out.writeUTF("Ana");
            out.writeInt(32);
            out.write(ANA.mPublicKey);
            out.writeInt(3);
            out.write(new byte[3]);
            out.writeLong(1);
            out.writeInt(0);
        }
        final Vault vault = Vault.deserialize(bytes.toByteArray());
        assertEquals("Ana", vault.getIdentities().get(0).mName);
        assertEquals(0, vault.getSessions().size());
    }

    @Test
    public void deletingAContactDeletesItsConversations() {
        final Vault vault = sample();
        vault.putSession(Ratchet.startAsInitiator(ANA, "id-ana", BETO.mPublicKey, "c-beto", 10));
        vault.removeContact("c-beto");
        assertEquals(0, vault.getSessions().size());
        assertNull(vault.activeSession("id-ana", "c-beto"));
    }

    @Test
    public void keepsTheNewestConversationsPerContact() {
        final Vault vault = sample();
        Ratchet.Session newest = null;
        for (int i = 0; i < Vault.MAX_SESSIONS_PER_CONTACT + 2; i++) {
            newest = Ratchet.startAsInitiator(ANA, "id-ana", BETO.mPublicKey, "c-beto", 100 + i);
            vault.putSession(newest);
        }
        assertEquals(Vault.MAX_SESSIONS_PER_CONTACT, vault.sessionsFor("id-ana", "c-beto").size());
        assertSame(newest, vault.activeSession("id-ana", "c-beto"));
    }
}
