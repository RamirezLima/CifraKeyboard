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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public class RatchetTest {
    private static final long HOUR = 60L * 60 * 1000;

    /** One device: an identity, one contact and its conversations with that contact. */
    private static final class Party {
        final String mName;
        final CifraCrypto.KeyPair mKeys;
        byte[] mContact;
        final List<Ratchet.Session> mSessions = new ArrayList<>();
        long mNow = 1_000_000;
        long mReread;

        Party(final String name, final String mnemonic, final String passphrase) {
            mName = name;
            mKeys = CifraCrypto.deriveKeyPair(Bip39.toSeed(Bip39.split(mnemonic), passphrase));
        }

        Ratchet.Session active() {
            return mSessions.get(mSessions.size() - 1);
        }

        byte[] send(final String text) {
            if (mSessions.isEmpty()) {
                mSessions.add(Ratchet.startAsInitiator(mKeys, mName, mContact, "contact", mNow));
            }
            return Ratchet.encrypt(active(), text, mNow);
        }

        /** Mirrors what the vault does: conversations first, then a new conversation. */
        Ratchet.Result receive(final byte[] wire) {
            Ratchet.Status best = Ratchet.Status.NOT_MINE;
            for (int i = 0; i < mSessions.size(); i++) {
                final Ratchet.Result result = Ratchet.decrypt(mSessions.get(i), wire, mNow,
                        mReread);
                if (result.mStatus == Ratchet.Status.OK) {
                    mSessions.set(i, result.mSession);
                    // The conversation that just received becomes the one used to answer.
                    mSessions.add(mSessions.remove(i));
                    return result;
                }
                if (result.mStatus != Ratchet.Status.NOT_MINE) {
                    best = result.mStatus;
                }
            }
            final Ratchet.Result initial = Ratchet.tryInitial(mKeys, mName, mContact, "contact",
                    wire, mNow, mReread);
            if (initial.mStatus == Ratchet.Status.OK) {
                for (final Ratchet.Session session : mSessions) {
                    if (session.startedWith(initial.mSession.getFirstRemoteRatchet())) {
                        return Ratchet.Result.of(Ratchet.Status.ALREADY_READ);
                    }
                }
                mSessions.add(initial.mSession);
                return initial;
            }
            return Ratchet.Result.of(best);
        }

        String read(final byte[] wire) {
            final Ratchet.Result result = receive(wire);
            assertEquals(mName + " should read the message", Ratchet.Status.OK, result.mStatus);
            return result.mPlaintext;
        }
    }

    private static Party[] pair() {
        final Party ana = new Party("ana", "legal winner thank year wave sausage worth useful "
                + "legal winner thank yellow", "");
        final Party beto = new Party("beto", "ozone drill grab fiber curtain grace pudding thank "
                + "cruise elder eight picnic", "");
        ana.mContact = beto.mKeys.mPublicKey;
        beto.mContact = ana.mKeys.mPublicKey;
        return new Party[] { ana, beto };
    }

    @Test
    public void conversationInBothDirections() {
        final Party[] p = pair();
        final Party ana = p[0];
        final Party beto = p[1];
        assertEquals("oi beto", beto.read(ana.send("oi beto")));
        assertTrue(ana.active().isUnanswered());
        assertEquals("oi ana", ana.read(beto.send("oi ana")));
        assertFalse(ana.active().isUnanswered());
        for (int i = 0; i < 5; i++) {
            assertEquals("a" + i, beto.read(ana.send("a" + i)));
            assertEquals("b" + i, ana.read(beto.send("b" + i)));
        }
    }

    @Test
    public void onlyTheFirstChainReliesOnIdentityKeys() {
        final Party[] p = pair();
        final Party ana = p[0];
        final Party beto = p[1];
        assertTrue(beto.receive(ana.send("first")).mFirstChain);
        assertTrue(beto.receive(ana.send("second, still unanswered")).mFirstChain);
        assertFalse(ana.receive(beto.send("answer")).mFirstChain);
        assertFalse(beto.receive(ana.send("after the answer")).mFirstChain);
    }

    @Test
    public void outOfOrderAndLostMessages() {
        final Party[] p = pair();
        final Party ana = p[0];
        final Party beto = p[1];
        final byte[] m1 = ana.send("1");
        final byte[] m2 = ana.send("2");
        final byte[] m3 = ana.send("3");
        assertEquals("3", beto.read(m3));
        assertEquals("1", beto.read(m1));
        assertEquals("ok", ana.read(beto.send("ok")));
        final byte[] m4 = ana.send("4");
        final byte[] m5 = ana.send("5");
        assertEquals("5", beto.read(m5));
        assertEquals("4", beto.read(m4));
        // m2 arrives late, from a chain that has already been replaced.
        assertEquals("2", beto.read(m2));
    }

    @Test
    public void tooManyLostMessagesAreRejected() {
        final Party[] p = pair();
        final Party ana = p[0];
        final Party beto = p[1];
        beto.read(ana.send("hello"));
        ana.read(beto.send("hi"));
        for (int i = 0; i <= Ratchet.MAX_SKIP; i++) {
            ana.send("lost " + i);
        }
        assertEquals(Ratchet.Status.TOO_FAR, beto.receive(ana.send("too far")).mStatus);
    }

    @Test
    public void readOnceBurnsTheKey() {
        final Party[] p = pair();
        final Party ana = p[0];
        final Party beto = p[1];
        beto.read(ana.send("start"));
        ana.read(beto.send("reply"));
        final byte[] message = ana.send("secret");
        assertEquals("secret", beto.read(message));
        assertEquals(Ratchet.Status.ALREADY_READ, beto.receive(message).mStatus);
    }

    @Test
    public void oldFirstMessageDoesNotRestartTheConversation() {
        final Party[] p = pair();
        final Party ana = p[0];
        final Party beto = p[1];
        final byte[] first = ana.send("first");
        beto.read(first);
        ana.read(beto.send("reply"));
        beto.read(ana.send("third"));
        final int sessions = beto.mSessions.size();
        assertEquals(Ratchet.Status.ALREADY_READ, beto.receive(first).mStatus);
        assertEquals(sessions, beto.mSessions.size());
        assertEquals("still fine", beto.read(ana.send("still fine")));
    }

    @Test
    public void rereadWindow() {
        final Party[] p = pair();
        final Party ana = p[0];
        final Party beto = p[1];
        beto.mReread = HOUR;
        beto.read(ana.send("start"));
        ana.read(beto.send("reply"));
        final byte[] message = ana.send("read me twice");
        assertEquals("read me twice", beto.read(message));
        final Ratchet.Result again = beto.receive(message);
        assertEquals(Ratchet.Status.OK, again.mStatus);
        assertTrue(again.mReread);
        beto.mNow += HOUR + 1;
        assertEquals(Ratchet.Status.ALREADY_READ, beto.receive(message).mStatus);
    }

    @Test
    public void tamperingAndStrangersAreRejected() {
        final Party[] p = pair();
        final Party ana = p[0];
        final Party beto = p[1];
        final Party eva = new Party("eva", "abandon abandon abandon abandon abandon abandon "
                + "abandon abandon abandon abandon abandon about", "");
        eva.mContact = ana.mKeys.mPublicKey;
        final byte[] message = ana.send("for beto only");
        assertEquals(Ratchet.Status.NOT_MINE, eva.receive(message).mStatus);
        for (final int position : new int[] { 5, 3 + Ratchet.HEADER_CIPHER + 3,
                message.length - 1 }) {
            final byte[] tampered = message.clone();
            tampered[position] ^= 1;
            assertEquals(Ratchet.Status.NOT_MINE, beto.receive(tampered).mStatus);
        }
        assertEquals("for beto only", beto.read(message));
    }

    @Test
    public void stolenStateDoesNotOpenThePast() {
        final Party[] p = pair();
        final Party ana = p[0];
        final Party beto = p[1];
        beto.read(ana.send("start"));
        ana.read(beto.send("reply"));
        final byte[] old = ana.send("old secret");
        beto.read(old);
        ana.read(beto.send("ok"));
        beto.read(ana.send("newer"));
        // Someone copies Beto's current state: the old message stays closed.
        final Ratchet.Session stolen = beto.active().copy();
        assertTrue(Ratchet.decrypt(stolen, old, beto.mNow, 0).mStatus
                != Ratchet.Status.OK);
    }

    @Test
    public void newDeviceRestartsTheConversation() {
        final Party[] p = pair();
        final Party ana = p[0];
        final Party beto = p[1];
        beto.read(ana.send("hello"));
        ana.read(beto.send("hi"));
        // Ana restores her words on a new phone: no conversations there.
        final Party newAna = new Party("ana", "legal winner thank year wave sausage worth useful "
                + "legal winner thank yellow", "");
        newAna.mContact = beto.mKeys.mPublicKey;
        final Ratchet.Result restarted = beto.receive(newAna.send("new phone"));
        assertEquals(Ratchet.Status.OK, restarted.mStatus);
        assertTrue(restarted.mFirstChain);
        assertEquals("welcome back", newAna.read(beto.send("welcome back")));
    }

    @Test
    public void bothSidesStartAtTheSameTime() {
        final Party[] p = pair();
        final Party ana = p[0];
        final Party beto = p[1];
        final byte[] fromAna = ana.send("ana first");
        final byte[] fromBeto = beto.send("beto first");
        assertEquals("ana first", beto.read(fromAna));
        assertEquals("beto first", ana.read(fromBeto));
        for (int i = 0; i < 3; i++) {
            assertEquals("a" + i, beto.read(ana.send("a" + i)));
            assertEquals("b" + i, ana.read(beto.send("b" + i)));
        }
    }

    @Test
    public void stateSurvivesSerialization() throws Exception {
        final Party[] p = pair();
        final Party ana = p[0];
        final Party beto = p[1];
        beto.mReread = HOUR;
        beto.read(ana.send("one"));
        ana.read(beto.send("two"));
        ana.send("skipped");
        beto.read(ana.send("three"));
        for (final Party party : p) {
            for (int i = 0; i < party.mSessions.size(); i++) {
                party.mSessions.set(i, Ratchet.Session.deserialize(
                        party.mSessions.get(i).serialize()));
            }
        }
        assertEquals("four", ana.read(beto.send("four")));
        assertEquals("five", beto.read(ana.send("five")));
    }

    @Test
    public void messagesAreRandomizedAndPadded() {
        final Party[] p = pair();
        final byte[] a = p[0].send("same");
        final byte[] b = p[0].send("same");
        assertNotNull(a);
        assertFalse(java.util.Arrays.equals(a, b));
        assertEquals(a.length, p[0].send("a bit longer than the others").length);
        assertTrue(Ratchet.isRatchetMessage(CifraCrypto.dearmor(CifraCrypto.armor(a))));
    }
}
