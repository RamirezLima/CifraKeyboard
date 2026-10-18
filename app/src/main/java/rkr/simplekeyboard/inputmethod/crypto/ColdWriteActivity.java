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

import android.app.ActionBar;
import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.EditText;

import java.lang.ref.WeakReference;

import rkr.simplekeyboard.inputmethod.R;

/**
 * Writing area of the cold phone: a text field that only exists to open the keyboard, where
 * messages are written in secure mode and shown as QR codes. It holds no keys, so it does not
 * ask for the screen lock; the keyboard asks when the vault opens. Anything typed outside secure
 * mode is erased when the screen is left.
 */
public final class ColdWriteActivity extends Activity {
    /** Tells the keyboard that this field is the writing area. */
    static final String PRIVATE_IME_OPTION = "org.cifra.keyboard.coldWrite";

    /** Main thread only. */
    private static WeakReference<ColdWriteActivity> sResumed = new WeakReference<>(null);

    private EditText mText;

    /**
     * Opens the camera from this screen, so it stays in the app's own task instead of showing up
     * as a separate window, as it does when the keyboard opens it.
     *
     * @return false if the writing area is not on screen.
     */
    static boolean scanHere(final int kind, final boolean holdsKeys,
            final QrScanActivity.Callback callback) {
        final ColdWriteActivity activity = sResumed.get();
        if (activity == null || activity.isFinishing()) {
            return false;
        }
        QrScanActivity.request(activity, kind, holdsKeys, callback);
        return true;
    }

    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.cifra_activity_cold_write);
        setTitle(R.string.cifra_cold_write_title);
        final ActionBar actionBar = getActionBar();
        if (actionBar != null) {
            actionBar.setDisplayHomeAsUpEnabled(true);
        }
        final View root = findViewById(R.id.cifra_cold_root);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            final int padding = root.getPaddingLeft();
            root.setOnApplyWindowInsetsListener((view, windowInsets) -> {
                final android.graphics.Insets insets = windowInsets.getInsets(
                        WindowInsets.Type.systemBars() | WindowInsets.Type.ime());
                // The top inset includes the action bar, which overlays the content.
                view.setPadding(padding + insets.left, padding + insets.top,
                        padding + insets.right, padding + insets.bottom);
                return WindowInsets.CONSUMED;
            });
        }
        mText = findViewById(R.id.cifra_cold_text);
        mText.setPrivateImeOptions(PRIVATE_IME_OPTION);
        mText.requestFocus();
    }

    @Override
    protected void onResume() {
        super.onResume();
        sResumed = new WeakReference<>(this);
    }

    @Override
    protected void onPause() {
        if (sResumed.get() == this) {
            sResumed.clear();
        }
        super.onPause();
    }

    @Override
    protected void onStop() {
        mText.setText(null);
        super.onStop();
    }

    @Override
    public boolean onOptionsItemSelected(final MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
