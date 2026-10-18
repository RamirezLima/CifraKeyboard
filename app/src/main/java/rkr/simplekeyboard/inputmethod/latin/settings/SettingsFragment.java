/*
 * Copyright (C) 2008 The Android Open Source Project
 * Copyright (C) 2026 Ramirez Lima
 * Copyright (C) 2025 Raimondas Rimkus
 * Copyright (C) 2021 wittmane
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

package rkr.simplekeyboard.inputmethod.latin.settings;

import android.app.AlertDialog;
import android.os.Bundle;
import android.preference.PreferenceScreen;

import rkr.simplekeyboard.inputmethod.R;
import rkr.simplekeyboard.inputmethod.crypto.SecureDialogs;
import rkr.simplekeyboard.inputmethod.latin.utils.ApplicationUtils;

public final class SettingsFragment extends InputMethodSettingsFragment {
    @Override
    public void onCreate(final Bundle icicle) {
        super.onCreate(icicle);
        setHasOptionsMenu(true);
        addPreferencesFromResource(R.xml.prefs);
        final PreferenceScreen preferenceScreen = getPreferenceScreen();
        preferenceScreen.setTitle(
                ApplicationUtils.getActivityTitleResId(getActivity(), SettingsActivity.class));

        // Shown in the app instead of a web page: the keyboard has no network access and should
        // not send people to a browser.
        findPreference("privacy_policy").setOnPreferenceClickListener(preference -> {
            showText(R.string.privacy_policy, R.string.cifra_privacy_text);
            return true;
        });
        findPreference("license").setOnPreferenceClickListener(preference -> {
            showText(R.string.license, R.string.cifra_license_text);
            return true;
        });
    }

    private void showText(final int title, final int text) {
        SecureDialogs.show(new AlertDialog.Builder(getActivity())
                .setTitle(title)
                .setMessage(text)
                .setPositiveButton(android.R.string.ok, null));
    }
}
