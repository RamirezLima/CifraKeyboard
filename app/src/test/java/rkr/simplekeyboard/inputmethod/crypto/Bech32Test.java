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

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class Bech32Test {
    // Valid string from BIP-0173, whose 5-bit values are 0..31 (exactly 20 bytes).
    private static final String BIP173_VECTOR = "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";
    private static final byte[] BIP173_BYTES = Hex.decode("00443214c74254b635cf84653a56d7c675be77df");

    @Test
    public void bip173Vector() {
        assertArrayEquals(BIP173_BYTES, Bech32.decode("abcdef", BIP173_VECTOR));
        assertArrayEquals(BIP173_BYTES, Bech32.decode("abcdef", BIP173_VECTOR.toUpperCase()));
        assertEquals(BIP173_VECTOR, Bech32.encode("abcdef", BIP173_BYTES));
    }

    @Test
    public void rejectsInvalid() {
        // Wrong checksum, wrong hrp, mixed case, invalid character.
        assertNull(Bech32.decode("abcdef", "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxx"));
        assertNull(Bech32.decode("cifra", BIP173_VECTOR));
        assertNull(Bech32.decode("abcdef", "abcdef1Qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw"));
        assertNull(Bech32.decode("abcdef", "abcdef1bpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw"));
    }
}
