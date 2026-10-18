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

import java.io.ByteArrayOutputStream;
import java.util.Locale;

/**
 * Bech32 encoding (BIP-0173). Used for public keys because it has no ambiguous characters and
 * detects typos, which matters when keys are read aloud or typed by hand.
 */
public final class Bech32 {
    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[] GENERATOR =
            { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    private static final int CHECKSUM_LENGTH = 6;

    private Bech32() {
        // This utility class is not publicly instantiable.
    }

    public static String encode(final String hrp, final byte[] data) {
        final byte[] values = convertBits(data, 8, 5, true);
        final byte[] checksum = createChecksum(hrp, values);
        final StringBuilder sb = new StringBuilder(hrp.length() + 1 + values.length
                + CHECKSUM_LENGTH);
        sb.append(hrp).append('1');
        for (final byte value : values) {
            sb.append(CHARSET.charAt(value));
        }
        for (final byte value : checksum) {
            sb.append(CHARSET.charAt(value));
        }
        return sb.toString();
    }

    /**
     * @return the decoded bytes, or null if the string is not valid Bech32 for the given hrp.
     */
    public static byte[] decode(final String expectedHrp, final String encoded) {
        if (encoded.length() < 8) {
            return null;
        }
        final String lower = encoded.toLowerCase(Locale.ROOT);
        if (!lower.equals(encoded) && !encoded.toUpperCase(Locale.ROOT).equals(encoded)) {
            return null; // Mixed case is not allowed.
        }
        final int separator = lower.lastIndexOf('1');
        if (separator < 1 || separator + 1 + CHECKSUM_LENGTH > lower.length()) {
            return null;
        }
        final String hrp = lower.substring(0, separator);
        if (!hrp.equals(expectedHrp)) {
            return null;
        }
        final byte[] values = new byte[lower.length() - separator - 1];
        for (int i = 0; i < values.length; i++) {
            final int value = CHARSET.indexOf(lower.charAt(separator + 1 + i));
            if (value < 0) {
                return null;
            }
            values[i] = (byte) value;
        }
        if (polymod(hrp, values) != 1) {
            return null;
        }
        final byte[] payload = new byte[values.length - CHECKSUM_LENGTH];
        System.arraycopy(values, 0, payload, 0, payload.length);
        return convertBits(payload, 5, 8, false);
    }

    private static int polymod(final String hrp, final byte[] values) {
        int chk = 1;
        for (int i = 0; i < hrp.length(); i++) {
            chk = polymodStep(chk, hrp.charAt(i) >> 5);
        }
        chk = polymodStep(chk, 0);
        for (int i = 0; i < hrp.length(); i++) {
            chk = polymodStep(chk, hrp.charAt(i) & 31);
        }
        for (final byte value : values) {
            chk = polymodStep(chk, value);
        }
        return chk;
    }

    private static int polymodStep(final int chk, final int value) {
        final int top = chk >>> 25;
        int result = ((chk & 0x1ffffff) << 5) ^ value;
        for (int i = 0; i < 5; i++) {
            if (((top >>> i) & 1) != 0) {
                result ^= GENERATOR[i];
            }
        }
        return result;
    }

    private static byte[] createChecksum(final String hrp, final byte[] values) {
        final byte[] padded = new byte[values.length + CHECKSUM_LENGTH];
        System.arraycopy(values, 0, padded, 0, values.length);
        final int mod = polymod(hrp, padded) ^ 1;
        final byte[] checksum = new byte[CHECKSUM_LENGTH];
        for (int i = 0; i < CHECKSUM_LENGTH; i++) {
            checksum[i] = (byte) ((mod >>> (5 * (5 - i))) & 31);
        }
        return checksum;
    }

    private static byte[] convertBits(final byte[] data, final int fromBits, final int toBits,
            final boolean pad) {
        int acc = 0;
        int bits = 0;
        final int maxValue = (1 << toBits) - 1;
        final ByteArrayOutputStream out = new ByteArrayOutputStream(data.length * fromBits / toBits
                + 1);
        for (final byte b : data) {
            final int value = b & 0xff;
            if ((value >>> fromBits) != 0) {
                return null;
            }
            acc = (acc << fromBits) | value;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                out.write((acc >>> bits) & maxValue);
            }
        }
        if (pad) {
            if (bits > 0) {
                out.write((acc << (toBits - bits)) & maxValue);
            }
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxValue) != 0) {
            return null;
        }
        return out.toByteArray();
    }
}
