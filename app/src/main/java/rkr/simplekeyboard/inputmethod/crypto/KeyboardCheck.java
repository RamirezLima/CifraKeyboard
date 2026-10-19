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
import android.app.Application;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.inputmethod.InputMethodInfo;
import android.view.inputmethod.InputMethodManager;

/**
 * Whether Cifra is the keyboard in use, and the system screens that make it so. Whatever is typed
 * goes through the keyboard in use, so a secret typed with another one never had Cifra's
 * protection.
 */
public final class KeyboardCheck {
    public enum State {
        /** Not turned on in the Android settings. */
        NOT_ENABLED,
        /** Turned on, but another keyboard is in use. */
        NOT_CURRENT,
        CURRENT,
    }

    /** The system learns that a window has the focus a moment after the window does. */
    private static final long PICKER_DELAY_MILLIS = 300;

    /** Main thread only: offered once per visit, not on every focus or every screen. */
    private static boolean sOffered;
    /** This app's started screens; back to zero means the user left the app. */
    private static int sStartedScreens;
    private static boolean sTracking;

    private KeyboardCheck() {
        // This utility class is not publicly instantiable.
    }

    /**
     * Counts this app's started screens, so one visit can be told from the next. Call from
     * onCreate of the screens that offer the switch, before they start.
     */
    public static void trackVisits(final Activity activity) {
        if (sTracking) {
            return;
        }
        sTracking = true;
        activity.getApplication().registerActivityLifecycleCallbacks(
                new Application.ActivityLifecycleCallbacks() {
                    @Override
                    public void onActivityStarted(final Activity started) {
                        sStartedScreens++;
                    }

                    @Override
                    public void onActivityStopped(final Activity stopped) {
                        if (sStartedScreens > 0) {
                            sStartedScreens--;
                        }
                        if (sStartedScreens == 0 && !stopped.isChangingConfigurations()) {
                            // Left the app: the next visit offers the switch again.
                            sOffered = false;
                        }
                    }

                    @Override
                    public void onActivityCreated(final Activity created, final Bundle state) {}

                    @Override
                    public void onActivityResumed(final Activity resumed) {}

                    @Override
                    public void onActivityPaused(final Activity paused) {}

                    @Override
                    public void onActivitySaveInstanceState(final Activity saved,
                            final Bundle state) {}

                    @Override
                    public void onActivityDestroyed(final Activity destroyed) {}
                });
    }

    /**
     * Opens the system list of keyboards when Cifra is turned on but another keyboard is in use,
     * once per visit to the app. Call from onWindowFocusChanged(true).
     */
    public static void offerSwitch(final Activity activity) {
        if (sOffered || state(activity) != State.NOT_CURRENT) {
            return;
        }
        sOffered = true;
        activity.getWindow().getDecorView().postDelayed(() -> {
            if (activity.isFinishing() || !activity.hasWindowFocus()) {
                // Something else took the focus: try again when this screen has it back.
                sOffered = false;
                return;
            }
            if (state(activity) == State.NOT_CURRENT) {
                showPicker(activity);
            }
        }, PICKER_DELAY_MILLIS);
    }

    public static State state(final Context context) {
        final InputMethodManager imm = context.getSystemService(InputMethodManager.class);
        if (imm == null) {
            return State.NOT_ENABLED;
        }
        final String packageName = context.getPackageName();
        boolean enabled = false;
        for (final InputMethodInfo info : imm.getEnabledInputMethodList()) {
            if (packageName.equals(info.getPackageName())) {
                enabled = true;
                break;
            }
        }
        if (!enabled) {
            return State.NOT_ENABLED;
        }
        return packageName.equals(currentPackage(context, imm)) ? State.CURRENT
                : State.NOT_CURRENT;
    }

    private static String currentPackage(final Context context, final InputMethodManager imm) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            final InputMethodInfo current = imm.getCurrentInputMethodInfo();
            if (current != null) {
                return current.getPackageName();
            }
        }
        final String id = Settings.Secure.getString(context.getContentResolver(),
                Settings.Secure.DEFAULT_INPUT_METHOD);
        final ComponentName component = id == null ? null : ComponentName.unflattenFromString(id);
        return component == null ? null : component.getPackageName();
    }

    /** Changes when the keyboard in use changes, for a content observer. */
    public static Uri currentKeyboardUri() {
        return Settings.Secure.getUriFor(Settings.Secure.DEFAULT_INPUT_METHOD);
    }

    /**
     * The system list for switching keyboards. Android only shows it to the app whose window has
     * the focus, so call it from a focused activity.
     */
    public static void showPicker(final Context context) {
        final InputMethodManager imm = context.getSystemService(InputMethodManager.class);
        if (imm != null) {
            imm.showInputMethodPicker();
        }
    }

    /** The Android settings where keyboards are turned on. */
    public static void openSettings(final Context context) {
        context.startActivity(new Intent(Settings.ACTION_INPUT_METHOD_SETTINGS));
    }
}
