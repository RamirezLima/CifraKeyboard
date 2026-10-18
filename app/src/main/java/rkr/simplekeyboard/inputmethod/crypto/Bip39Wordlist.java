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

import android.content.Context;

import java.io.IOException;

import rkr.simplekeyboard.inputmethod.R;

/**
 * The official BIP39 English wordlist, bundled as a raw resource. It is the only list supported:
 * the other languages are discouraged by the BIP39 authors and poorly supported by other tools,
 * so a backup written with them is easy to lose.
 */
public final class Bip39Wordlist {
    private static Bip39 sEnglish;

    private Bip39Wordlist() {
        // This utility class is not publicly instantiable.
    }

    public static synchronized Bip39 get(final Context context) {
        if (sEnglish == null) {
            try {
                sEnglish = Bip39.load(context.getResources().openRawResource(
                        R.raw.bip39_english));
            } catch (IOException e) {
                throw new IllegalStateException("Cannot read the BIP39 wordlist", e);
            }
        }
        return sEnglish;
    }
}
