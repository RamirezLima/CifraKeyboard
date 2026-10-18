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
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * QR codes between a phone with internet and a cold phone that never goes online.
 *
 * Only encrypted messages and public keys travel this way: the cold phone is where messages are
 * written and read. Messages go as their binary wire format, a third smaller than the armored
 * text; public keys go as their "cifra1..." text. One QR code per message: {@link #MAX_BYTES}
 * keeps it at version 20 (97 × 97 modules), which a phone camera still reads from another
 * phone's screen.
 */
public final class QrCodes {
    /** Byte capacity of a version 20 QR code at error correction level L. */
    public static final int MAX_BYTES = 858;
    /**
     * Largest plaintext, in UTF-8 bytes, whose message fits {@link #MAX_BYTES} in both formats:
     * three padding blocks minus the length prefix.
     */
    public static final int MAX_PLAINTEXT_BYTES = 3 * CifraCrypto.PADDING_BLOCK - 4;
    /** Blank modules around the code, as the QR specification asks. */
    static final int QUIET_ZONE = 4;

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
        return wire.length <= MAX_BYTES;
    }

    /**
     * Encodes a message in its wire format, one module per bit plus the quiet zone.
     *
     * @throws IllegalArgumentException if the message does not fit one QR code.
     */
    public static BitMatrix encodeMessage(final byte[] wire) {
        if (!fits(wire)) {
            throw new IllegalArgumentException("Message too long for a QR code");
        }
        // Without a character set hint the bytes go in byte mode as ISO-8859-1, which maps each
        // byte to one character, and no ECI header takes room.
        return encode(new String(wire, StandardCharsets.ISO_8859_1), ErrorCorrectionLevel.L);
    }

    /** Encodes a short text, such as a public key. */
    public static BitMatrix encodeText(final String text) {
        return encode(text, ErrorCorrectionLevel.M);
    }

    private static BitMatrix encode(final String contents, final ErrorCorrectionLevel level) {
        final Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
        hints.put(EncodeHintType.ERROR_CORRECTION, level);
        hints.put(EncodeHintType.MARGIN, QUIET_ZONE);
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
     * @return the wire bytes of the Cifra message in a QR code, or null if it has none. Also
     *     accepts the armored text, as another app would show it.
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
