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
import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceCategory;
import android.preference.PreferenceFragment;
import android.preference.PreferenceScreen;
import android.preference.SwitchPreference;
import android.text.Editable;
import android.text.InputType;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import rkr.simplekeyboard.inputmethod.R;

/**
 * "Keys and contacts" settings screen: identities derived from BIP39 words, contacts' public
 * keys, and erasing everything.
 */
public final class CryptoSettingsFragment extends PreferenceFragment {
    private VaultStore mStore;

    @Override
    public void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mStore = VaultStore.getInstance(getActivity());
        // The keyboard reads its settings from device protected storage; keep the switches there.
        getPreferenceManager().setStorageDeviceProtected();
        setPreferenceScreen(getPreferenceManager().createPreferenceScreen(getActivity()));
        getActivity().setTitle(R.string.cifra_settings_title);
    }

    @Override
    public void onResume() {
        super.onResume();
        rebuild();
    }

    private void rebuild() {
        final Activity activity = getActivity();
        final PreferenceScreen screen = getPreferenceScreen();
        screen.removeAll();

        final Vault vault;
        try {
            vault = mStore.getVault();
        } catch (VaultStore.VaultException e) {
            screen.addPreference(info(errorMessage(e), null));
            if (e.mReason == VaultStore.VaultException.Reason.KEY_LOST) {
                addSecurityCategory(screen);
            }
            return;
        }

        final KeyguardManager keyguard = activity.getSystemService(KeyguardManager.class);
        if (keyguard != null && !keyguard.isDeviceSecure()) {
            screen.addPreference(info(getString(R.string.cifra_no_lock_screen), null));
        }

        final PreferenceCategory identities = category(screen, R.string.cifra_identities);
        final Vault.Identity defaultIdentity = vault.getDefaultIdentity();
        for (final Vault.Identity identity : vault.getIdentities()) {
            final boolean isDefault = vault.getIdentities().size() > 1
                    && identity == defaultIdentity;
            final Preference preference = new Preference(activity);
            preference.setTitle(identity.mName);
            preference.setSummary(getString(R.string.cifra_fingerprint, identity.getFingerprint())
                    + (isDefault ? "\n" + getString(R.string.cifra_default_identity) : ""));
            preference.setOnPreferenceClickListener(p -> {
                showIdentity(identity);
                return true;
            });
            identities.addPreference(preference);
        }
        final Preference addIdentity = action(R.string.cifra_add_identity,
                R.string.cifra_add_identity_summary);
        addIdentity.setOnPreferenceClickListener(p -> {
            startActivity(new Intent(activity, IdentitySetupActivity.class));
            return true;
        });
        identities.addPreference(addIdentity);

        final PreferenceCategory contacts = category(screen, R.string.cifra_contacts);
        for (final Vault.Contact contact : vault.getContacts()) {
            final Preference preference = new Preference(activity);
            preference.setTitle(contact.mVerified ? contact.mName + "  ✓" : contact.mName);
            preference.setSummary(getString(R.string.cifra_fingerprint, contact.getFingerprint())
                    + "\n" + getString(contact.mVerified ? R.string.cifra_verified
                            : R.string.cifra_not_verified));
            preference.setOnPreferenceClickListener(p -> {
                showContact(contact);
                return true;
            });
            contacts.addPreference(preference);
        }
        final Preference addContact = action(R.string.cifra_add_contact,
                R.string.cifra_add_contact_summary);
        addContact.setOnPreferenceClickListener(p -> {
            showAddContact();
            return true;
        });
        contacts.addPreference(addContact);

        addSecurityCategory(screen);
    }

    private void addSecurityCategory(final PreferenceScreen screen) {
        final PreferenceCategory security = category(screen, R.string.cifra_security);
        security.addPreference(info(getString(R.string.cifra_about_title),
                getString(R.string.cifra_about_summary)));
        final SwitchPreference screenReader = new SwitchPreference(getActivity());
        screenReader.setKey(SecureKeyboard.PREF_SCREEN_READER);
        screenReader.setDefaultValue(false);
        screenReader.setTitle(R.string.cifra_screen_reader_title);
        screenReader.setSummaryOff(R.string.cifra_screen_reader_summary_off);
        screenReader.setSummaryOn(Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
                ? R.string.cifra_screen_reader_summary_on
                : R.string.cifra_screen_reader_summary_on_legacy);
        security.addPreference(screenReader);
        final Preference wipe = action(R.string.cifra_wipe, R.string.cifra_wipe_summary);
        wipe.setOnPreferenceClickListener(p -> {
            SecureDialogs.show(new AlertDialog.Builder(getActivity())
                    .setMessage(R.string.cifra_wipe_confirm)
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(R.string.cifra_delete, (d, w) -> {
                        mStore.wipeEverything();
                        toast(R.string.cifra_wiped);
                        rebuild();
                    }));
            return true;
        });
        security.addPreference(wipe);
    }

    private void showIdentity(final Vault.Identity identity) {
        SecureDialogs.show(new AlertDialog.Builder(getActivity())
                .setTitle(identity.mName)
                .setView(keyInfoView(identity.getEncodedPublicKey(), identity.getFingerprint(),
                        null))
                .setPositiveButton(R.string.cifra_share_public_key, (d, w) -> share(identity))
                .setNeutralButton(R.string.cifra_copy_public_key,
                        (d, w) -> copy(identity.getEncodedPublicKey()))
                .setNegativeButton("…", (d, w) -> showIdentityActions(identity)));
    }

    private void showIdentityActions(final Vault.Identity identity) {
        final CharSequence[] items = {
            getString(R.string.cifra_set_default),
            getString(R.string.cifra_rename),
            getString(R.string.cifra_delete),
        };
        SecureDialogs.show(new AlertDialog.Builder(getActivity())
                .setTitle(identity.mName)
                .setItems(items, (d, which) -> {
                    switch (which) {
                        case 0:
                            run(() -> mStore.setDefaultIdentity(identity.mId));
                            break;
                        case 1:
                            askName(identity.mName,
                                    name -> run(() -> mStore.renameIdentity(identity.mId, name)));
                            break;
                        default:
                            confirmDelete(getString(R.string.cifra_delete_identity_confirm,
                                    identity.mName),
                                    () -> run(() -> mStore.removeIdentity(identity.mId)));
                            break;
                    }
                }));
    }

    private void showContact(final Vault.Contact contact) {
        SecureDialogs.show(new AlertDialog.Builder(getActivity())
                .setTitle(contact.mName)
                .setView(keyInfoView(contact.getEncodedPublicKey(), contact.getFingerprint(),
                        getString(R.string.cifra_verify_hint, contact.mName)))
                .setPositiveButton(contact.mVerified ? R.string.cifra_mark_unverified
                        : R.string.cifra_mark_verified,
                        (d, w) -> run(() -> mStore.setContactVerified(contact.mId,
                                !contact.mVerified)))
                .setNeutralButton(R.string.cifra_copy_public_key,
                        (d, w) -> copy(contact.getEncodedPublicKey()))
                .setNegativeButton("…", (d, w) -> showContactActions(contact)));
    }

    private void showContactActions(final Vault.Contact contact) {
        final CharSequence[] items = {
            getString(R.string.cifra_rename),
            getString(R.string.cifra_delete),
        };
        SecureDialogs.show(new AlertDialog.Builder(getActivity())
                .setTitle(contact.mName)
                .setItems(items, (d, which) -> {
                    if (which == 0) {
                        askName(contact.mName,
                                name -> run(() -> mStore.renameContact(contact.mId, name)));
                    } else {
                        confirmDelete(getString(R.string.cifra_delete_contact_confirm,
                                contact.mName), () -> run(() -> mStore.removeContact(contact.mId)));
                    }
                }));
    }

    private void showAddContact() {
        final View view = LayoutInflater.from(getActivity())
                .inflate(R.layout.cifra_dialog_add_contact, null);
        final EditText name = view.findViewById(R.id.cifra_contact_name);
        final EditText key = view.findViewById(R.id.cifra_contact_key);
        final TextView fingerprint = view.findViewById(R.id.cifra_contact_fingerprint);
        key.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {}

            @Override
            public void afterTextChanged(final Editable s) {
                final byte[] publicKey = CifraCrypto.findPublicKey(s);
                if (publicKey != null) {
                    fingerprint.setText(getString(R.string.cifra_fingerprint,
                            CifraCrypto.fingerprint(publicKey)));
                } else {
                    fingerprint.setText(s.length() == 0 ? null
                            : getString(R.string.cifra_invalid_public_key));
                }
            }
        });
        // Offer the key that was just copied from a chat or e-mail.
        final ClipboardManager clipboard = getActivity().getSystemService(ClipboardManager.class);
        final ClipData clip = clipboard == null ? null : clipboard.getPrimaryClip();
        if (clip != null && clip.getItemCount() > 0) {
            final CharSequence text = clip.getItemAt(0).getText();
            final byte[] publicKey = CifraCrypto.findPublicKey(text);
            if (publicKey != null) {
                key.setText(CifraCrypto.encodePublicKey(publicKey));
            }
        }

        final AlertDialog dialog = SecureDialogs.show(new AlertDialog.Builder(getActivity())
                .setTitle(R.string.cifra_add_contact)
                .setView(view)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.cifra_add_contact, null));
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            final String contactName = name.getText().toString().trim();
            final byte[] publicKey = CifraCrypto.findPublicKey(key.getText());
            if (contactName.isEmpty()) {
                name.setError(getString(R.string.cifra_name_required));
                return;
            }
            if (publicKey == null) {
                key.setError(getString(R.string.cifra_invalid_public_key));
                return;
            }
            try {
                mStore.addContact(contactName, publicKey);
            } catch (VaultStore.VaultException e) {
                key.setError(e.mReason == VaultStore.VaultException.Reason.DUPLICATE
                        ? getString(R.string.cifra_duplicate_contact) : errorMessage(e));
                return;
            }
            dialog.dismiss();
            rebuild();
        });
    }

    private View keyInfoView(final String encodedKey, final String fingerprint,
            final String hint) {
        final View view = LayoutInflater.from(getActivity())
                .inflate(R.layout.cifra_dialog_key_info, null);
        ((TextView) view.findViewById(R.id.cifra_key_value)).setText(encodedKey);
        ((TextView) view.findViewById(R.id.cifra_key_fingerprint)).setText(fingerprint);
        final TextView hintView = view.findViewById(R.id.cifra_key_hint);
        hintView.setText(hint);
        hintView.setVisibility(hint == null ? View.GONE : View.VISIBLE);
        return view;
    }

    private interface NameCallback {
        void onName(String name);
    }

    private void askName(final String current, final NameCallback callback) {
        final EditText input = new EditText(getActivity());
        // Names are metadata: keep them away from spell checkers and keyboard learning.
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_WORDS
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        input.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        }
        input.setText(current);
        input.setSelection(current.length());
        final int padding = (int) (20 * getResources().getDisplayMetrics().density);
        final android.widget.FrameLayout container = new android.widget.FrameLayout(getActivity());
        container.setPadding(padding, padding / 2, padding, 0);
        container.addView(input);
        SecureDialogs.show(new AlertDialog.Builder(getActivity())
                .setTitle(R.string.cifra_rename)
                .setView(container)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(android.R.string.ok, (d, w) -> {
                    final String name = input.getText().toString().trim();
                    if (!TextUtils.isEmpty(name)) {
                        callback.onName(name);
                    }
                }));
    }

    private void confirmDelete(final String message, final Runnable action) {
        SecureDialogs.show(new AlertDialog.Builder(getActivity())
                .setMessage(message)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.cifra_delete, (d, w) -> action.run()));
    }

    private interface VaultAction {
        void run() throws VaultStore.VaultException;
    }

    private void run(final VaultAction action) {
        try {
            action.run();
        } catch (VaultStore.VaultException e) {
            Toast.makeText(getActivity(), errorMessage(e), Toast.LENGTH_LONG).show();
        }
        rebuild();
    }

    private void share(final Vault.Identity identity) {
        final Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TEXT, getString(R.string.cifra_share_text,
                identity.getEncodedPublicKey(), identity.getFingerprint()));
        startActivity(Intent.createChooser(intent, getString(R.string.cifra_share_public_key)));
    }

    private void copy(final String encodedKey) {
        final ClipboardManager clipboard = (ClipboardManager) getActivity()
                .getSystemService(Context.CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText(getString(R.string.cifra_public_key),
                encodedKey));
        toast(R.string.cifra_copied);
    }

    private String errorMessage(final VaultStore.VaultException e) {
        switch (e.mReason) {
            case DEVICE_LOCKED:
                return getString(R.string.cifra_error_locked);
            case KEY_LOST:
                return getString(R.string.cifra_error_key_lost);
            case DUPLICATE:
                return getString(R.string.cifra_duplicate_identity);
            default:
                return getString(R.string.cifra_error_generic);
        }
    }

    private void toast(final int message) {
        Toast.makeText(getActivity(), message, Toast.LENGTH_SHORT).show();
    }

    private PreferenceCategory category(final PreferenceScreen screen, final int title) {
        final PreferenceCategory category = new PreferenceCategory(getActivity());
        category.setTitle(title);
        screen.addPreference(category);
        return category;
    }

    private Preference action(final int title, final int summary) {
        final Preference preference = new Preference(getActivity());
        preference.setTitle(title);
        preference.setSummary(summary);
        return preference;
    }

    private Preference info(final String title, final String summary) {
        final Preference preference = new Preference(getActivity());
        preference.setTitle(title);
        preference.setSummary(summary);
        preference.setSelectable(false);
        return preference;
    }
}
