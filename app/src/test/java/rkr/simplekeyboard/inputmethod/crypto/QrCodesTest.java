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

import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.common.BitMatrix;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public class QrCodesTest {
    private static final CifraCrypto.KeyPair ANA = CifraCrypto.deriveKeyPair(Bip39.toSeed(
            Bip39.split("legal winner thank year wave sausage worth useful legal winner thank "
                    + "yellow"), ""));
    private static final CifraCrypto.KeyPair BETO = CifraCrypto.deriveKeyPair(Bip39.toSeed(
            Bip39.split("ozone drill grab fiber curtain grace pudding thank cruise elder eight "
                    + "picnic"), ""));

    /** Draws the code as a camera would see a screen: a few pixels per module. */
    private static QrCodes.Content scan(final BitMatrix matrix) {
        final int scale = 3;
        final int size = matrix.getWidth() * scale;
        final int[] pixels = new int[size * size];
        for (int y = 0; y < size; y++) {
            for (int x = 0; x < size; x++) {
                pixels[y * size + x] = matrix.get(x / scale, y / scale) ? 0xFF000000 : 0xFFFFFFFF;
            }
        }
        return QrCodes.decode(new RGBLuminanceSource(size, size, pixels), false);
    }

    private static int version(final BitMatrix matrix) {
        final int modules = matrix.getWidth() - 2 * QrCodes.QUIET_ZONE;
        return (modules - 17) / 4;
    }

    private static String text(final int bytes) {
        final char[] chars = new char[bytes];
        Arrays.fill(chars, 'a');
        return new String(chars);
    }

    private static byte[] ratchetMessage(final String text) {
        return Ratchet.encrypt(Ratchet.startAsInitiator(ANA, "ana", BETO.mPublicKey, "beto", 1),
                text, 1);
    }

    /** Reads the loop like a camera would: out of order, some codes twice. */
    private static byte[] readLoop(final List<BitMatrix> codes) {
        final List<BitMatrix> seen = new ArrayList<>(codes);
        seen.addAll(codes.subList(0, Math.min(2, codes.size())));
        Collections.shuffle(seen, new Random(7));
        final QrCodes.Assembler assembler = new QrCodes.Assembler();
        byte[] wire = null;
        for (final BitMatrix code : seen) {
            final byte[] done = assembler.add(scan(code));
            if (done != null) {
                assertNull("only one complete message", wire);
                wire = done;
            }
        }
        return wire;
    }

    @Test
    public void messagesRoundTripAsLoopsOfSmallCodes() throws Exception {
        for (final byte[] wire : new byte[][] {
                ratchetMessage("oi"),
                ratchetMessage(text(QrCodes.MAX_PLAINTEXT_BYTES)),
                CifraCrypto.seal(text(QrCodes.MAX_PLAINTEXT_BYTES), BETO.mPublicKey, ANA) }) {
            assertTrue(QrCodes.fits(wire));
            final List<BitMatrix> codes = QrCodes.encodeMessage(wire);
            assertTrue(codes.size() <= QrCodes.MAX_PARTS);
            for (final BitMatrix code : codes) {
                // Small codes survive a camera slightly out of focus; all the same size.
                assertTrue(version(code) <= 6);
                assertEquals(version(codes.get(0)), version(code));
            }
            assertArrayEquals(wire, readLoop(codes));
        }
    }

    @Test
    public void longerMessagesDoNotFit() {
        assertFalse(QrCodes.fits(ratchetMessage(text(QrCodes.MAX_PLAINTEXT_BYTES + 1))));
    }

    @Test
    public void anotherMessageStartsOver() {
        final List<BitMatrix> first = QrCodes.encodeMessage(ratchetMessage("first"));
        final byte[] second = ratchetMessage("second");
        final List<BitMatrix> codes = QrCodes.encodeMessage(second);
        final QrCodes.Assembler assembler = new QrCodes.Assembler();
        for (int i = 0; i < first.size() - 1; i++) {
            assertNull(assembler.add(scan(first.get(i))));
        }
        byte[] wire = null;
        for (final BitMatrix code : codes) {
            wire = assembler.add(scan(code));
        }
        assertArrayEquals(second, wire);
    }

    @Test
    public void damagedPartIsRejected() {
        final byte[] wire = ratchetMessage("hello");
        final byte[][] parts = QrCodes.split(wire);
        final QrCodes.Assembler assembler = new QrCodes.Assembler();
        final byte[] damaged = parts[1].clone();
        damaged[QrCodes.PART_HEADER + 3] ^= 1;
        assertNull(assembler.add(new QrCodes.Content(damaged, null)));
        for (int i = 0; i < parts.length; i++) {
            if (i != 1) {
                assertNull(assembler.add(new QrCodes.Content(parts[i], null)));
            }
        }
        // Complete, but the check failed: the loop has to be read again, and then it works.
        for (final byte[] part : parts) {
            final byte[] done = assembler.add(new QrCodes.Content(part, null));
            if (done != null) {
                assertArrayEquals(wire, done);
                return;
            }
        }
        throw new AssertionError("the message was not read again");
    }

    @Test
    public void singleCodesAreStillRead() throws Exception {
        final byte[] wire = CifraCrypto.seal("oi", BETO.mPublicKey, ANA);
        // The wire format in one code, as the first version showed it.
        final QrCodes.Content binary = scan(QrCodes.encodeText(
                new String(wire, StandardCharsets.ISO_8859_1)));
        assertArrayEquals(wire, QrCodes.messageWire(binary));
        // The armored text, as another app would show it.
        assertArrayEquals(wire, QrCodes.messageWire(scan(QrCodes.encodeText(
                CifraCrypto.armor(wire)))));
        assertFalse(QrCodes.isPart(binary));
    }

    @Test
    public void publicKeyRoundTrips() {
        final String encoded = CifraCrypto.encodePublicKey(ANA.mPublicKey);
        final QrCodes.Content content = scan(QrCodes.encodeText(encoded));
        assertArrayEquals(ANA.mPublicKey, QrCodes.publicKey(content));
        assertNull(QrCodes.messageWire(content));
    }

    @Test
    public void otherCodesAreIgnored() {
        final QrCodes.Content content = scan(QrCodes.encodeText("https://example.com"));
        assertNotNull(content);
        assertNull(QrCodes.messageWire(content));
        assertNull(QrCodes.publicKey(content));
        assertFalse(QrCodes.isPart(content));
        assertNull(new QrCodes.Assembler().add(content));
        assertNull(QrCodes.messageWire(null));
    }
}
