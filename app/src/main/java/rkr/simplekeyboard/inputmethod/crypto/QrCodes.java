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

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.EncodeHintType;
import com.google.zxing.LuminanceSource;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.ReaderException;
import com.google.zxing.Result;
import com.google.zxing.ResultMetadataType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * QR codes between a phone with internet and a cold phone that never goes online.
 *
 * Only encrypted messages and public keys travel this way: the cold phone is where messages are
 * written and read. Public keys go as their "cifra1..." text in one small code.
 *
 * A message goes as a loop of small codes, each with a part of its binary wire format. One dense
 * code would be enough, but a phone camera pointed at another phone's screen is often slightly
 * out of focus, and ZXing loses dense codes long before small ones: with about 115 bytes per
 * code, the modules are half again as large and survive twice the blur. The reader collects
 * the parts in any order.
 *
 * Each part: "CQ", version 1, the first 4 bytes of the message's SHA-256, the part's index and
 * the number of parts (1 byte each), the message length (2 bytes), and the data, all parts the
 * same size so the codes do not change size as they cycle.
 */
public final class QrCodes {
    /** Message bytes per code: with the header, a version 6 code (41 × 41 modules). */
    static final int PART_DATA = 110;
    static final int PART_HEADER = 11;
    /** About 5 seconds per loop at 4 codes per second. */
    public static final int MAX_PARTS = 20;
    /**
     * Largest plaintext, in UTF-8 bytes, whose message fits {@link #MAX_PARTS} codes in both
     * formats: eight padding blocks minus the length prefix.
     */
    public static final int MAX_PLAINTEXT_BYTES = 8 * CifraCrypto.PADDING_BLOCK - 4;
    /** Blank modules around the code, as the QR specification asks. */
    static final int QUIET_ZONE = 4;
    /** Pixels per module a camera may see; every part must be found at all of them. */
    private static final int[] CHECK_SCALES = { 2, 3, 4, 5, 6, 8 };
    private static final int NUM_MASKS = 8;
    private static final byte[] PART_MAGIC = { 'C', 'Q', 1 };

    /** What a QR code carried. */
    public static final class Content {
        /** The bytes of its byte mode segments, or null if it had none. */
        public final byte[] mBytes;
        public final String mText;

        Content(final byte[] bytes, final String text) {
            mBytes = bytes;
            mText = text;
        }
    }

    private QrCodes() {
        // This utility class is not publicly instantiable.
    }

    public static boolean fits(final byte[] wire) {
        return wire.length > 0 && wire.length <= MAX_PARTS * PART_DATA;
    }

    /**
     * Encodes a message as its loop of codes, one module per bit plus the quiet zone.
     *
     * @throws IllegalArgumentException if the message needs more than {@link #MAX_PARTS} codes.
     */
    public static List<BitMatrix> encodeMessage(final byte[] wire) {
        final List<BitMatrix> codes = new ArrayList<>();
        for (final byte[] part : split(wire)) {
            codes.add(encodeReadable(part));
        }
        return codes;
    }

    /**
     * ZXing's detector misses about 1 in 100 codes even when drawn perfectly: random data can
     * look like the corner squares. The data is fine, and another of the 8 masks draws it
     * differently, so each part is checked with the reader the other phone uses, at several
     * sizes, and redrawn with another mask when it is not found.
     */
    static BitMatrix encodeReadable(final byte[] part) {
        // Without a character set hint the bytes go in byte mode as ISO-8859-1, which maps each
        // byte to one character, and no ECI header takes room.
        final String contents = new String(part, StandardCharsets.ISO_8859_1);
        BitMatrix first = null;
        for (int mask = -1; mask < NUM_MASKS; mask++) {
            // -1: the mask the encoder picks by itself.
            final BitMatrix code = encode(contents, ErrorCorrectionLevel.L, mask);
            if (first == null) {
                first = code;
            }
            if (readableAtEveryScale(code, part)) {
                return code;
            }
        }
        return first;
    }

    static boolean readableAtEveryScale(final BitMatrix code, final byte[] expected) {
        for (final int scale : CHECK_SCALES) {
            final Content content = decode(render(code, scale), false);
            if (content == null || !Arrays.equals(expected, content.mBytes)) {
                return false;
            }
        }
        return true;
    }

    private static LuminanceSource render(final BitMatrix code, final int scale) {
        final int size = code.getWidth() * scale;
        final byte[] luminance = new byte[size * size];
        for (int y = 0; y < size; y++) {
            for (int x = 0; x < size; x++) {
                luminance[y * size + x] = code.get(x / scale, y / scale) ? 0 : (byte) 255;
            }
        }
        return new PlanarYUVLuminanceSource(luminance, size, size, 0, 0, size, size, false);
    }

    static byte[][] split(final byte[] wire) {
        if (!fits(wire)) {
            throw new IllegalArgumentException("Message too long for QR codes");
        }
        final int count = (wire.length + PART_DATA - 1) / PART_DATA;
        final int size = (wire.length + count - 1) / count;
        final int id = messageId(wire);
        final byte[][] parts = new byte[count][];
        for (int i = 0; i < count; i++) {
            // The last part is padded with zeros; the length in the header cuts them off.
            final byte[] part = new byte[PART_HEADER + size];
            System.arraycopy(PART_MAGIC, 0, part, 0, PART_MAGIC.length);
            part[3] = (byte) (id >>> 24);
            part[4] = (byte) (id >>> 16);
            part[5] = (byte) (id >>> 8);
            part[6] = (byte) id;
            part[7] = (byte) i;
            part[8] = (byte) count;
            part[9] = (byte) (wire.length >>> 8);
            part[10] = (byte) wire.length;
            final int offset = i * size;
            System.arraycopy(wire, offset, part, PART_HEADER,
                    Math.min(size, wire.length - offset));
            parts[i] = part;
        }
        return parts;
    }

    private static int messageId(final byte[] wire) {
        try {
            final byte[] hash = MessageDigest.getInstance("SHA-256").digest(wire);
            return ((hash[0] & 0xff) << 24) | ((hash[1] & 0xff) << 16) | ((hash[2] & 0xff) << 8)
                    | (hash[3] & 0xff);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** @return whether a code is one part of a message. */
    public static boolean isPart(final Content content) {
        final byte[] bytes = content == null ? null : content.mBytes;
        if (bytes == null || bytes.length <= PART_HEADER) {
            return false;
        }
        for (int i = 0; i < PART_MAGIC.length; i++) {
            if (bytes[i] != PART_MAGIC[i]) {
                return false;
            }
        }
        final int index = bytes[7] & 0xff;
        final int count = bytes[8] & 0xff;
        final int length = ((bytes[9] & 0xff) << 8) | (bytes[10] & 0xff);
        final int size = bytes.length - PART_HEADER;
        return count > 0 && count <= MAX_PARTS && index < count && length > 0
                && length <= count * size && length > (count - 1) * size;
    }

    /** Puts a message back together from its codes, read in any order and any number of times. */
    public static final class Assembler {
        private int mId;
        private int mLength;
        private byte[][] mParts;
        private int mReceived;

        /** @return the whole message once its last missing part arrives, otherwise null. */
        public byte[] add(final Content content) {
            if (!isPart(content)) {
                return null;
            }
            final byte[] bytes = content.mBytes;
            final int id = ((bytes[3] & 0xff) << 24) | ((bytes[4] & 0xff) << 16)
                    | ((bytes[5] & 0xff) << 8) | (bytes[6] & 0xff);
            final int index = bytes[7] & 0xff;
            final int count = bytes[8] & 0xff;
            final int length = ((bytes[9] & 0xff) << 8) | (bytes[10] & 0xff);
            if (mParts == null || id != mId || count != mParts.length || length != mLength) {
                // Another message: start over.
                mId = id;
                mLength = length;
                mParts = new byte[count][];
                mReceived = 0;
            }
            if (mParts[index] == null) {
                mParts[index] = Arrays.copyOfRange(bytes, PART_HEADER, bytes.length);
                mReceived++;
            }
            if (mReceived < count) {
                return null;
            }
            final byte[] wire = new byte[length];
            int offset = 0;
            for (final byte[] part : mParts) {
                final int n = Math.min(part.length, length - offset);
                if (n < 0 || part.length != mParts[0].length) {
                    reset();
                    return null;
                }
                System.arraycopy(part, 0, wire, offset, n);
                offset += n;
            }
            if (offset != length || messageId(wire) != id) {
                // A damaged part: read the whole loop again.
                reset();
                return null;
            }
            reset();
            return wire;
        }

        public int received() {
            return mReceived;
        }

        public int total() {
            return mParts == null ? 0 : mParts.length;
        }

        private void reset() {
            mParts = null;
            mReceived = 0;
        }
    }

    /** Encodes a short text, such as a public key. */
    public static BitMatrix encodeText(final String text) {
        return encode(text, ErrorCorrectionLevel.M, -1);
    }

    private static BitMatrix encode(final String contents, final ErrorCorrectionLevel level,
            final int mask) {
        final Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
        hints.put(EncodeHintType.ERROR_CORRECTION, level);
        hints.put(EncodeHintType.MARGIN, QUIET_ZONE);
        if (mask >= 0) {
            hints.put(EncodeHintType.QR_MASK_PATTERN, mask);
        }
        try {
            return new QRCodeWriter().encode(contents, BarcodeFormat.QR_CODE, 0, 0, hints);
        } catch (WriterException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Looks for a QR code in an image.
     *
     * @param tryHarder slower, for a still image rather than a stream of camera frames.
     * @return what the code carried, or null if there is no readable code.
     */
    public static Content decode(final LuminanceSource source, final boolean tryHarder) {
        final Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
        hints.put(DecodeHintType.POSSIBLE_FORMATS, Collections.singletonList(BarcodeFormat.QR_CODE));
        hints.put(DecodeHintType.CHARACTER_SET, StandardCharsets.ISO_8859_1.name());
        if (tryHarder) {
            hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
        }
        final Result result;
        try {
            result = new QRCodeReader().decode(new BinaryBitmap(new HybridBinarizer(source)),
                    hints);
        } catch (ReaderException e) {
            return null;
        }
        return new Content(byteSegments(result), result.getText());
    }

    private static byte[] byteSegments(final Result result) {
        final Map<ResultMetadataType, Object> metadata = result.getResultMetadata();
        final Object segments = metadata == null ? null
                : metadata.get(ResultMetadataType.BYTE_SEGMENTS);
        if (!(segments instanceof List)) {
            return null;
        }
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        for (final Object segment : (List<?>) segments) {
            if (segment instanceof byte[]) {
                final byte[] part = (byte[]) segment;
                bytes.write(part, 0, part.length);
            }
        }
        return bytes.toByteArray();
    }

    /**
     * @return the wire bytes of a Cifra message in a single QR code, or null if it has none:
     *     the wire format, as the first version of the cold phone showed it, or the armored text,
     *     as another app would show it. Messages in parts go through {@link Assembler}.
     */
    public static byte[] messageWire(final Content content) {
        if (content == null) {
            return null;
        }
        final byte[] bytes = content.mBytes;
        if (bytes != null && (CifraCrypto.hasValidHeader(bytes)
                || Ratchet.isRatchetMessage(bytes))) {
            return bytes;
        }
        return CifraCrypto.dearmor(content.mText);
    }

    /** @return the public key in a QR code, or null if it has none. */
    public static byte[] publicKey(final Content content) {
        return content == null ? null : CifraCrypto.findPublicKey(content.mText);
    }
}
