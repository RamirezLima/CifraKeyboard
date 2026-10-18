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

import android.app.AlertDialog;
import android.view.WindowManager;

/**
 * Dialogs are separate windows and do not inherit FLAG_SECURE from their activity, so contact
 * names and keys shown in them would appear in screenshots, recordings and the assistant.
 */
public final class SecureDialogs {
    private SecureDialogs() {
        // This utility class is not publicly instantiable.
    }

    public static AlertDialog show(final AlertDialog.Builder builder) {
        final AlertDialog dialog = builder.create();
        dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        dialog.show();
        return dialog;
    }
}
