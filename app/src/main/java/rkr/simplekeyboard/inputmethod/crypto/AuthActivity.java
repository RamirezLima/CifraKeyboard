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

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Intent;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.view.WindowManager;

import rkr.simplekeyboard.inputmethod.R;

/**
 * Invisible screen that shows the system authentication prompt and reports the result to
 * {@link DeviceAuth}. Accepts the screen lock or a strong (class 3) biometric: weaker biometrics
 * do not unlock Keystore keys.
 */
public final class AuthActivity extends Activity {
    static final String EXTRA_REQUEST_ID = "cifra_auth_request";
    static final String EXTRA_TITLE = "cifra_auth_title";
    private static final int REQUEST_CONFIRM_CREDENTIAL = 1;

    private int mRequestId;
    private boolean mDelivered;
    private CancellationSignal mCancellationSignal;

    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        mRequestId = getIntent().getIntExtra(EXTRA_REQUEST_ID, -1);
        if (savedInstanceState != null) {
            // Recreated by the system: the prompt of the previous instance is gone.
            finishWith(false);
            return;
        }
        final CharSequence title = getIntent().getCharSequenceExtra(EXTRA_TITLE);
        // Android 9's prompt cannot fall back to the screen lock, so it gets the older screen.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            showBiometricPrompt(title);
        } else {
            showConfirmCredential(title);
        }
    }

    @TargetApi(Build.VERSION_CODES.Q)
    private void showBiometricPrompt(final CharSequence title) {
        final BiometricPrompt.Builder builder = new BiometricPrompt.Builder(this)
                .setTitle(title)
                .setSubtitle(getString(R.string.cifra_auth_subtitle));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
                    | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
        } else {
            builder.setDeviceCredentialAllowed(true);
        }
        mCancellationSignal = new CancellationSignal();
        builder.build().authenticate(mCancellationSignal, getMainExecutor(),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(
                            final BiometricPrompt.AuthenticationResult result) {
                        finishWith(true);
                    }

                    @Override
                    public void onAuthenticationError(final int errorCode,
                            final CharSequence errorString) {
                        finishWith(false);
                    }
                });
    }

    @SuppressWarnings("deprecation")
    private void showConfirmCredential(final CharSequence title) {
        final KeyguardManager keyguard = getSystemService(KeyguardManager.class);
        final Intent intent = keyguard == null ? null : keyguard.createConfirmDeviceCredentialIntent(
                title, getString(R.string.cifra_auth_subtitle));
        if (intent == null) {
            finishWith(false);
            return;
        }
        startActivityForResult(intent, REQUEST_CONFIRM_CREDENTIAL);
    }

    @Override
    protected void onActivityResult(final int requestCode, final int resultCode,
            final Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_CONFIRM_CREDENTIAL) {
            finishWith(resultCode == RESULT_OK);
        }
    }

    @SuppressWarnings("deprecation")
    private void finishWith(final boolean authenticated) {
        if (mDelivered) {
            return;
        }
        mDelivered = true;
        DeviceAuth.deliver(mRequestId, authenticated);
        finish();
        overridePendingTransition(0, 0);
    }

    @Override
    protected void onDestroy() {
        if (mCancellationSignal != null) {
            mCancellationSignal.cancel();
        }
        if (!mDelivered) {
            mDelivered = true;
            DeviceAuth.deliver(mRequestId, false);
        }
        super.onDestroy();
    }
}
