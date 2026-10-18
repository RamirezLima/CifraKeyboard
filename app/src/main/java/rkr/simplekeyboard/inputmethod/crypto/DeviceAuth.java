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

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.util.SparseArray;

/**
 * Asks the owner to confirm with the screen lock (PIN, pattern, password) or a strong biometric.
 *
 * The system only shows these prompts to the app in the foreground, which a keyboard never is,
 * so every request goes through {@link AuthActivity}. The result here only decides what the UI
 * shows: the real gate is the Keystore, which refuses to unwrap identity keys without a recent
 * authentication (see {@link VaultStore#AUTH_WINDOW_SECONDS}).
 *
 * Main thread only.
 */
public final class DeviceAuth {
    public interface Callback {
        void onResult(boolean authenticated);
    }

    private static final SparseArray<Callback> sPending = new SparseArray<>();
    private static int sNextRequestId;

    private DeviceAuth() {
        // This utility class is not publicly instantiable.
    }

    public static void request(final Context context, final CharSequence title,
            final Callback callback) {
        final int requestId = ++sNextRequestId;
        sPending.put(requestId, callback);
        final Intent intent = new Intent(context, AuthActivity.class)
                .putExtra(AuthActivity.EXTRA_REQUEST_ID, requestId)
                .putExtra(AuthActivity.EXTRA_TITLE, title)
                .addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION);
        if (!(context instanceof Activity)) {
            // From the keyboard service.
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        }
        try {
            context.startActivity(intent);
        } catch (RuntimeException e) {
            deliver(requestId, false);
        }
    }

    static void deliver(final int requestId, final boolean authenticated) {
        final Callback callback = sPending.get(requestId);
        sPending.remove(requestId);
        if (callback != null) {
            callback.onResult(authenticated);
        }
    }
}
