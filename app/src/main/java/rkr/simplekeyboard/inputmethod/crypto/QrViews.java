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
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.provider.Settings;
import android.view.View;
import android.view.WindowInsets;

import com.google.zxing.common.BitMatrix;

/** Android side of the QR codes: drawing them and the screens around them. */
final class QrViews {
    private QrViews() {
        // This utility class is not publicly instantiable.
    }

    /** One pixel per module, scaled without smoothing so the edges stay sharp at any size. */
    static Drawable drawable(final Resources resources, final BitMatrix matrix) {
        final int width = matrix.getWidth();
        final int height = matrix.getHeight();
        final int[] pixels = new int[width * height];
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                pixels[y * width + x] = matrix.get(x, y) ? Color.BLACK : Color.WHITE;
            }
        }
        final BitmapDrawable drawable = new BitmapDrawable(resources,
                Bitmap.createBitmap(pixels, width, height, Bitmap.Config.ARGB_8888));
        drawable.setFilterBitmap(false);
        return drawable;
    }

    /** Keeps the content clear of the status and navigation bars. */
    static void applyInsets(final View root) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return;
        }
        final int left = root.getPaddingLeft();
        final int top = root.getPaddingTop();
        final int right = root.getPaddingRight();
        final int bottom = root.getPaddingBottom();
        root.setOnApplyWindowInsetsListener((view, windowInsets) -> {
            final android.graphics.Insets insets = windowInsets.getInsets(
                    WindowInsets.Type.systemBars());
            view.setPadding(left + insets.left, top + insets.top, right + insets.right,
                    bottom + insets.bottom);
            return WindowInsets.CONSUMED;
        });
    }

    /**
     * A phone that holds keys and is online is not a cold phone. Airplane mode is the only part
     * of this an app can see without the network state permission, which Cifra does not have.
     */
    static boolean shouldWarnOnline(final Context context, final boolean holdsKeys) {
        return holdsKeys && Settings.Global.getInt(context.getContentResolver(),
                Settings.Global.AIRPLANE_MODE_ON, 0) == 0;
    }

    static void showOnlineWarning(final Context context, final View warning,
            final boolean holdsKeys) {
        warning.setVisibility(shouldWarnOnline(context, holdsKeys) ? View.VISIBLE : View.GONE);
    }
}
