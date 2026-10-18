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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.List;

public class Bip39Test {
    private static Bip39 sEnglish;

    @BeforeClass
    public static void setUp() throws IOException {
        // Unit tests run with the module directory as the working directory.
        try (FileInputStream in = new FileInputStream("src/main/res/raw/bip39_english.txt")) {
            sEnglish = Bip39.load(in);
        }
    }

    // Official vectors from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    private static final String[][] TREZOR_VECTORS = {
        {
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        },
        {
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
        },
        {
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"
        },
        {
            "9e885d952ad362caeb4efe34a8e91bd2",
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
            "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028"
        },
        {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
        },
    };

    @Test
    public void trezorVectors() throws Exception {
        for (final String[] vector : TREZOR_VECTORS) {
            final byte[] entropy = Hex.decode(vector[0]);
            final String[] words = sEnglish.entropyToMnemonic(entropy);
            assertEquals(vector[1], Bip39.join(words));
            assertArrayEquals(entropy, sEnglish.mnemonicToEntropy(Bip39.split(vector[1])));
            assertEquals(vector[2], Hex.toHexString(Bip39.toSeed(words, "TREZOR")));
        }
    }

    @Test
    public void splitIsCaseAndSpaceInsensitive() throws Exception {
        final String[] words = Bip39.split("  Legal WINNER thank\nyear  wave sausage worth "
                + "useful legal winner thank yellow ");
        sEnglish.validate(words);
        assertEquals(12, words.length);
        assertEquals("legal", words[0]);
    }

    @Test
    public void canonicalizeLowercases() {
        final String[] canonical = sEnglish.canonicalize(new String[] { "Abandon", "ZOO" });
        assertArrayEquals(new String[] { "abandon", "zoo" }, canonical);
        assertNull(sEnglish.canonicalize(new String[] { "notaword" }));
    }

    @Test
    public void rejectsWordsFromOtherLanguages() {
        // First words of the Portuguese and Spanish BIP39 lists, which are not supported.
        assertInvalid("abacate abaixo abalar abater abdicar abelha aberto abismo abacate abacate "
                + "abacate abater", Bip39.InvalidMnemonicException.Reason.UNKNOWN_WORD, 0);
        assertInvalid("abandon ábaco abandon abandon abandon abandon abandon abandon abandon "
                + "abandon abandon about", Bip39.InvalidMnemonicException.Reason.UNKNOWN_WORD, 1);
    }

    @Test
    public void rejectsBadChecksum() {
        assertInvalid("abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                + "abandon abandon abandon", Bip39.InvalidMnemonicException.Reason.CHECKSUM, -1);
    }

    @Test
    public void rejectsUnknownWord() {
        assertInvalid("abandon abandon abandon abandon abandon abandonn abandon abandon abandon "
                + "abandon abandon about", Bip39.InvalidMnemonicException.Reason.UNKNOWN_WORD, 5);
    }

    @Test
    public void rejectsWordCount() {
        assertInvalid("abandon abandon about", Bip39.InvalidMnemonicException.Reason.WORD_COUNT,
                -1);
    }

    @Test
    public void generateProducesValidMnemonics() throws Exception {
        final SecureRandom random = new SecureRandom();
        for (final int count : new int[] { 12, 24 }) {
            final String[] words = sEnglish.generate(count, random);
            assertEquals(count, words.length);
            sEnglish.validate(words);
        }
        assertNotEquals(Bip39.join(sEnglish.generate(12, random)),
                Bip39.join(sEnglish.generate(12, random)));
    }

    @Test
    public void wordlistIsSorted() {
        final List<String> words = sEnglish.getWords();
        for (int i = 1; i < words.size(); i++) {
            assertTrue(words.get(i - 1).compareTo(words.get(i)) < 0);
        }
    }

    private static void assertInvalid(final String mnemonic,
            final Bip39.InvalidMnemonicException.Reason reason, final int index) {
        try {
            sEnglish.validate(Bip39.split(mnemonic));
            fail("Expected an invalid mnemonic");
        } catch (Bip39.InvalidMnemonicException e) {
            assertEquals(reason, e.mReason);
            assertEquals(index, e.mWordIndex);
        }
    }
}
