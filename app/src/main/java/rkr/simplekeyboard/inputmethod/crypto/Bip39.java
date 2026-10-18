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

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * BIP-0039 mnemonic handling for a single 2048-word list.
 *
 * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */
public final class Bip39 {
    public static final int WORDLIST_SIZE = 2048;
    private static final int PBKDF2_ROUNDS = 2048;
    private static final int SEED_BITS = 512;

    private final List<String> mWords;
    private final Map<String, Integer> mIndex;

    public Bip39(final List<String> words) {
        if (words.size() != WORDLIST_SIZE) {
            throw new IllegalArgumentException("A BIP39 wordlist needs " + WORDLIST_SIZE
                    + " words, got " + words.size());
        }
        mWords = Collections.unmodifiableList(new ArrayList<>(words));
        mIndex = new HashMap<>(WORDLIST_SIZE * 2);
        for (int i = 0; i < WORDLIST_SIZE; i++) {
            mIndex.put(lookupKey(mWords.get(i)), i);
        }
        if (mIndex.size() != WORDLIST_SIZE) {
            throw new IllegalArgumentException("The wordlist has duplicated words");
        }
    }

    public static Bip39 load(final InputStream in) throws IOException {
        final List<String> words = new ArrayList<>(WORDLIST_SIZE);
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) {
                    words.add(line);
                }
            }
        }
        return new Bip39(words);
    }

    public List<String> getWords() {
        return mWords;
    }

    public boolean contains(final String word) {
        return mIndex.containsKey(lookupKey(word));
    }

    /**
     * @return the words as spelled in the wordlist (e.g. lowercase), or null if one of them is
     * not in the list.
     */
    public String[] canonicalize(final String[] words) {
        final String[] canonical = new String[words.length];
        for (int i = 0; i < words.length; i++) {
            final Integer index = mIndex.get(lookupKey(words[i]));
            if (index == null) {
                return null;
            }
            canonical[i] = mWords.get(index);
        }
        return canonical;
    }

    /**
     * Splits the text typed by the user into normalized words.
     */
    public static String[] split(final CharSequence mnemonic) {
        final String normalized = normalize(mnemonic.toString()).trim();
        if (normalized.isEmpty()) {
            return new String[0];
        }
        return normalized.split("\\s+");
    }

    public static boolean isValidWordCount(final int count) {
        return count >= 12 && count <= 24 && count % 3 == 0;
    }

    public String[] generate(final int wordCount, final SecureRandom random) {
        if (!isValidWordCount(wordCount)) {
            throw new IllegalArgumentException("Invalid word count " + wordCount);
        }
        final byte[] entropy = new byte[wordCount * 4 / 3];
        random.nextBytes(entropy);
        try {
            return entropyToMnemonic(entropy);
        } finally {
            Arrays.fill(entropy, (byte) 0);
        }
    }

    public String[] entropyToMnemonic(final byte[] entropy) {
        if (entropy.length < 16 || entropy.length > 32 || entropy.length % 4 != 0) {
            throw new IllegalArgumentException("Invalid entropy length " + entropy.length);
        }
        final int entropyBits = entropy.length * 8;
        final int checksumBits = entropyBits / 32;
        final byte[] hash = sha256(entropy);
        final int wordCount = (entropyBits + checksumBits) / 11;
        final String[] words = new String[wordCount];
        for (int w = 0; w < wordCount; w++) {
            int index = 0;
            for (int b = 0; b < 11; b++) {
                final int bit = w * 11 + b;
                index <<= 1;
                if (bit < entropyBits) {
                    index |= getBit(entropy, bit);
                } else {
                    index |= getBit(hash, bit - entropyBits);
                }
            }
            words[w] = mWords.get(index);
        }
        return words;
    }

    /**
     * @return the entropy encoded by the words.
     * @throws InvalidMnemonicException when a word is unknown, the number of words is not
     * supported or the checksum does not match.
     */
    public byte[] mnemonicToEntropy(final String[] words) throws InvalidMnemonicException {
        if (!isValidWordCount(words.length)) {
            throw new InvalidMnemonicException(InvalidMnemonicException.Reason.WORD_COUNT, -1);
        }
        final int totalBits = words.length * 11;
        final int checksumBits = totalBits / 33;
        final int entropyBits = totalBits - checksumBits;
        final byte[] bits = new byte[(totalBits + 7) / 8];
        for (int w = 0; w < words.length; w++) {
            final Integer index = mIndex.get(lookupKey(words[w]));
            if (index == null) {
                throw new InvalidMnemonicException(InvalidMnemonicException.Reason.UNKNOWN_WORD, w);
            }
            for (int b = 0; b < 11; b++) {
                if ((index & (1 << (10 - b))) != 0) {
                    final int bit = w * 11 + b;
                    bits[bit / 8] |= (byte) (1 << (7 - (bit % 8)));
                }
            }
        }
        final byte[] entropy = Arrays.copyOf(bits, entropyBits / 8);
        final byte[] hash = sha256(entropy);
        for (int i = 0; i < checksumBits; i++) {
            if (getBit(bits, entropyBits + i) != getBit(hash, i)) {
                Arrays.fill(bits, (byte) 0);
                Arrays.fill(entropy, (byte) 0);
                throw new InvalidMnemonicException(InvalidMnemonicException.Reason.CHECKSUM, -1);
            }
        }
        Arrays.fill(bits, (byte) 0);
        return entropy;
    }

    public void validate(final String[] words) throws InvalidMnemonicException {
        Arrays.fill(mnemonicToEntropy(words), (byte) 0);
    }

    /**
     * Converts a mnemonic into the 64 byte BIP39 seed. This does not validate the words, as
     * mandated by the specification; call {@link #validate(String[])} first.
     */
    public static byte[] toSeed(final String[] words, final CharSequence passphrase) {
        final String sentence = normalize(join(words));
        final String salt = "mnemonic" + Normalizer.normalize(
                passphrase == null ? "" : passphrase, Normalizer.Form.NFKD);
        final byte[] password = sentence.getBytes(StandardCharsets.UTF_8);
        final byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
        try {
            final PKCS5S2ParametersGenerator generator =
                    new PKCS5S2ParametersGenerator(new SHA512Digest());
            generator.init(password, saltBytes, PBKDF2_ROUNDS);
            return ((KeyParameter) generator.generateDerivedParameters(SEED_BITS)).getKey();
        } finally {
            Arrays.fill(password, (byte) 0);
            Arrays.fill(saltBytes, (byte) 0);
        }
    }

    public static String join(final String[] words) {
        final StringBuilder sb = new StringBuilder();
        for (final String word : words) {
            if (sb.length() > 0) {
                sb.append(' ');
            }
            sb.append(word);
        }
        return sb.toString();
    }

    private static String normalize(final String text) {
        return Normalizer.normalize(text, Normalizer.Form.NFKD).toLowerCase(Locale.ROOT);
    }

    private static String lookupKey(final String word) {
        return normalize(word);
    }

    private static int getBit(final byte[] data, final int bit) {
        return (data[bit / 8] >> (7 - (bit % 8))) & 1;
    }

    private static byte[] sha256(final byte[] data) {
        final SHA256Digest digest = new SHA256Digest();
        digest.update(data, 0, data.length);
        final byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    public static final class InvalidMnemonicException extends Exception {
        public enum Reason { WORD_COUNT, UNKNOWN_WORD, CHECKSUM }

        public final Reason mReason;
        /** Index of the offending word, or -1 when the problem is not a single word. */
        public final int mWordIndex;

        InvalidMnemonicException(final Reason reason, final int wordIndex) {
            super(reason.name());
            mReason = reason;
            mWordIndex = wordIndex;
        }
    }
}
