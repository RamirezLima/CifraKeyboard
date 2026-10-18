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

import java.security.SecureRandom;
import java.util.Arrays;

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

    @Test
    public void largestPayloadRoundTripsAtVersion20() {
        final byte[] wire = new byte[QrCodes.MAX_BYTES];
        new SecureRandom().nextBytes(wire);
        final BitMatrix matrix = QrCodes.encodeMessage(wire);
        assertEquals(20, version(matrix));
        final QrCodes.Content content = scan(matrix);
        assertNotNull(content);
        assertArrayEquals(wire, content.mBytes);
    }

    @Test(expected = IllegalArgumentException.class)
    public void oneByteMoreDoesNotFit() {
        QrCodes.encodeMessage(new byte[QrCodes.MAX_BYTES + 1]);
    }

    @Test
    public void longestMessagesFitInBothFormats() throws Exception {
        final String longest = text(QrCodes.MAX_PLAINTEXT_BYTES);
        final byte[] ratchet = Ratchet.encrypt(Ratchet.startAsInitiator(ANA, "ana",
                BETO.mPublicKey, "beto", 1), longest, 1);
        final byte[] classic = CifraCrypto.seal(longest, BETO.mPublicKey, ANA);
        assertTrue(QrCodes.fits(ratchet));
        assertTrue(QrCodes.fits(classic));
        assertArrayEquals(ratchet, QrCodes.messageWire(scan(QrCodes.encodeMessage(ratchet))));
        assertArrayEquals(classic, QrCodes.messageWire(scan(QrCodes.encodeMessage(classic))));

        final byte[] tooLong = Ratchet.encrypt(Ratchet.startAsInitiator(ANA, "ana",
                BETO.mPublicKey, "beto", 1), text(QrCodes.MAX_PLAINTEXT_BYTES + 1), 1);
        assertFalse(QrCodes.fits(tooLong));
    }

    @Test
    public void armoredTextIsAlsoAccepted() throws Exception {
        final byte[] wire = CifraCrypto.seal("oi", BETO.mPublicKey, ANA);
        final QrCodes.Content content = scan(QrCodes.encodeText(CifraCrypto.armor(wire)));
        assertArrayEquals(wire, QrCodes.messageWire(content));
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
        assertNull(QrCodes.messageWire(null));
    }
}
