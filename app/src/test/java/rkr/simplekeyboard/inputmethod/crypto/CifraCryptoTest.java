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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class CifraCryptoTest {
    private static CifraCrypto.KeyPair identity(final String mnemonic, final String passphrase) {
        return CifraCrypto.deriveKeyPair(Bip39.toSeed(Bip39.split(mnemonic), passphrase));
    }

    private static final String ALICE = "legal winner thank year wave sausage worth useful legal "
            + "winner thank yellow";
    private static final String BOB = "ozone drill grab fiber curtain grace pudding thank cruise "
            + "elder eight picnic";

    @Test
    public void derivationIsDeterministicAndPassphraseDependent() {
        final CifraCrypto.KeyPair a1 = identity(ALICE, "");
        final CifraCrypto.KeyPair a2 = identity(ALICE, "");
        final CifraCrypto.KeyPair hidden = identity(ALICE, "outra senha");
        assertEquals(32, a1.mPublicKey.length);
        assertEquals(32, a1.mSecretKey.length);
        assertArrayEquals(a1.mPublicKey, a2.mPublicKey);
        assertArrayEquals(a1.mSecretKey, a2.mSecretKey);
        assertFalse(Hex.toHexString(a1.mPublicKey).equals(Hex.toHexString(hidden.mPublicKey)));
    }

    @Test
    public void knownAnswerFingerprint() {
        // Value shown by the app on an Android 17 emulator for the same words: derivation and
        // fingerprint must stay identical across platforms and versions.
        assertEquals("01984 54588 36266 68175 16727 91488",
                CifraCrypto.fingerprint(identity(ALICE, "").mPublicKey));
    }

    @Test
    public void sealAndOpen() throws Exception {
        final CifraCrypto.KeyPair alice = identity(ALICE, "");
        final CifraCrypto.KeyPair bob = identity(BOB, "");
        final String message = "Encontro às 19h na praça. Traga o pendrive 🔐";
        final byte[] wire = CifraCrypto.seal(message, bob.mPublicKey, alice);
        assertEquals(message, CifraCrypto.open(wire, bob, alice.mPublicKey));
    }

    @Test
    public void openFailsWithWrongSenderOrRecipient() throws Exception {
        final CifraCrypto.KeyPair alice = identity(ALICE, "");
        final CifraCrypto.KeyPair bob = identity(BOB, "");
        final CifraCrypto.KeyPair mallory = identity(ALICE, "mallory");
        final byte[] wire = CifraCrypto.seal("segredo", bob.mPublicKey, alice);
        // Someone else claiming to be the sender.
        assertNull(CifraCrypto.open(wire, bob, mallory.mPublicKey));
        // Someone who is not the recipient.
        assertNull(CifraCrypto.open(wire, mallory, alice.mPublicKey));
    }

    @Test
    public void tamperingIsDetected() throws Exception {
        final CifraCrypto.KeyPair alice = identity(ALICE, "");
        final CifraCrypto.KeyPair bob = identity(BOB, "");
        final byte[] wire = CifraCrypto.seal("segredo", bob.mPublicKey, alice);
        for (final int position : new int[] { 2, 10, wire.length - 1 }) {
            final byte[] tampered = wire.clone();
            tampered[position] ^= 1;
            assertNull(CifraCrypto.open(tampered, bob, alice.mPublicKey));
        }
    }

    @Test
    public void ciphertextIsRandomizedAndPadded() throws Exception {
        final CifraCrypto.KeyPair alice = identity(ALICE, "");
        final CifraCrypto.KeyPair bob = identity(BOB, "");
        final byte[] shortWire = CifraCrypto.seal("oi", bob.mPublicKey, alice);
        final byte[] longerWire = CifraCrypto.seal("uma mensagem um pouco maior", bob.mPublicKey,
                alice);
        assertEquals(shortWire.length, longerWire.length);
        assertFalse(Hex.toHexString(shortWire).equals(Hex.toHexString(
                CifraCrypto.seal("oi", bob.mPublicKey, alice))));
        // header + enc + one padding block + Poly1305 tag
        assertEquals(3 + 32 + CifraCrypto.PADDING_BLOCK + 16, shortWire.length);
    }

    @Test
    public void armorSurvivesMessengerMangling() throws Exception {
        final CifraCrypto.KeyPair alice = identity(ALICE, "");
        final CifraCrypto.KeyPair bob = identity(BOB, "");
        final byte[] wire = CifraCrypto.seal("teste", bob.mPublicKey, alice);
        final String armored = CifraCrypto.armor(wire);
        assertTrue(CifraCrypto.containsArmoredMessage(armored));

        // Quoted reply in an e-mail, with CRLF line breaks and text around it.
        final String quoted = "Re: oi\r\n\r\n> " + armored.replace("\n", "\r\n> ") + "\r\n\r\nabs";
        assertArrayEquals(wire, CifraCrypto.dearmor(quoted));
        // Chat app that collapsed all line breaks into spaces.
        assertArrayEquals(wire, CifraCrypto.dearmor(armored.replace('\n', ' ')));
        assertNull(CifraCrypto.dearmor("nada aqui"));
    }

    @Test
    public void publicKeyEncoding() {
        final CifraCrypto.KeyPair alice = identity(ALICE, "");
        final String encoded = CifraCrypto.encodePublicKey(alice.mPublicKey);
        assertTrue(encoded.startsWith("cifra1"));
        assertEquals(64, encoded.length());
        final String shared = "Minha chave Cifra:\n" + encoded + "\nConfira: "
                + CifraCrypto.fingerprint(alice.mPublicKey);
        assertArrayEquals(alice.mPublicKey, CifraCrypto.findPublicKey(shared));
        assertArrayEquals(alice.mPublicKey,
                CifraCrypto.findPublicKey(encoded.toUpperCase(java.util.Locale.ROOT)));

        // A single typo is caught by the checksum.
        final char[] typo = encoded.toCharArray();
        typo[20] = typo[20] == 'q' ? 'p' : 'q';
        assertNull(CifraCrypto.findPublicKey(new String(typo)));
    }

    @Test
    public void rejectsLowOrderPublicKeys() {
        assertFalse(CifraCrypto.isUsablePublicKey(new byte[32]));
        final byte[] one = new byte[32];
        one[0] = 1;
        assertFalse(CifraCrypto.isUsablePublicKey(one));
        assertFalse(CifraCrypto.isUsablePublicKey(new byte[31]));
        assertTrue(CifraCrypto.isUsablePublicKey(identity(BOB, "").mPublicKey));
    }

    @Test
    public void fingerprintFormat() {
        final String fingerprint = CifraCrypto.fingerprint(identity(ALICE, "").mPublicKey);
        assertTrue(fingerprint, fingerprint.matches("\\d{5}( \\d{5}){5}"));
    }

    @Test
    public void padRoundTrip() {
        for (final int length : new int[] { 0, 1, 251, 252, 253, 1000 }) {
            final byte[] message = new byte[length];
            for (int i = 0; i < length; i++) {
                message[i] = (byte) (i + 1);
            }
            final byte[] expected = message.clone();
            final byte[] padded = CifraCrypto.pad(message);
            assertEquals(0, padded.length % CifraCrypto.PADDING_BLOCK);
            assertArrayEquals(expected, CifraCrypto.unpad(padded));
        }
        assertNotNull(CifraCrypto.unpad(new byte[4]));
        assertNull(CifraCrypto.unpad(new byte[] { 0, 0, 1, 0 }));
    }
}
