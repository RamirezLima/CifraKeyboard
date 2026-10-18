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
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.preference.ListPreference;
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
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import rkr.simplekeyboard.inputmethod.R;

/**
 * "Keys and contacts" settings screen: identities derived from BIP39 words, contacts' public
 * keys, the cold phone, and erasing everything.
 */
public final class CryptoSettingsFragment extends PreferenceFragment {
    private VaultStore mStore;
    /** Every visit to this screen asks for the screen lock or a strong biometric. */
    private boolean mUnlocked;
    private boolean mAuthInProgress;
    /** The owner cancelled the prompt: wait for a tap instead of asking again in a loop. */
    private boolean mDeclined;
    /** Set while one of our own screens covers this one, so coming back does not lock it. */
    private boolean mOpeningOwnScreen;

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
        mOpeningOwnScreen = false;
        if (mUnlocked) {
            rebuild();
            return;
        }
        showLocked();
        if (!mDeclined) {
            requestUnlock();
        }
    }

    @Override
    public void onStop() {
        super.onStop();
        if (!mOpeningOwnScreen) {
            // Leaving the screen closes the vault: the next visit asks again.
            mUnlocked = false;
            mDeclined = false;
            getPreferenceScreen().removeAll();
        }
    }

    private void requestUnlock() {
        if (mAuthInProgress || !mStore.isDeviceSecure()) {
            return;
        }
        mAuthInProgress = true;
        DeviceAuth.request(getActivity(), getString(R.string.cifra_auth_title_settings),
                authenticated -> {
                    mAuthInProgress = false;
                    if (getActivity() == null) {
                        return;
                    }
                    if (authenticated) {
                        mUnlocked = true;
                        mDeclined = false;
                        rebuild();
                    } else {
                        mDeclined = true;
                        showLocked();
                    }
                });
    }

    private void showLocked() {
        final PreferenceScreen screen = getPreferenceScreen();
        screen.removeAll();
        if (!mStore.isDeviceSecure()) {
            screen.addPreference(info(getString(R.string.cifra_no_lock_screen), null));
        } else {
            final Preference unlock = action(R.string.cifra_locked_title,
                    R.string.cifra_locked_summary);
            unlock.setOnPreferenceClickListener(p -> {
                requestUnlock();
                return true;
            });
            screen.addPreference(unlock);
        }
        // What the device's secure hardware can do is not secret, and matters before the
        // first identity is created.
        screen.addPreference(keystorePreference());
        // Erasing never needs authentication: destroying the keys must always be possible.
        screen.addPreference(wipeAction());
        // Nothing secret either, and the phone with internet may hold no keys at all.
        addColdCategory(screen);
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
            mOpeningOwnScreen = true;
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

        addColdCategory(screen);
        addSecurityCategory(screen);
    }

    private void addColdCategory(final PreferenceScreen screen) {
        final PreferenceCategory cold = category(screen, R.string.cifra_cold);
        final SwitchPreference qr = new SwitchPreference(getActivity());
        qr.setKey(SecureKeyboard.PREF_QR);
        qr.setDefaultValue(false);
        qr.setTitle(R.string.cifra_qr_switch_title);
        qr.setSummaryOff(R.string.cifra_qr_switch_summary_off);
        qr.setSummaryOn(R.string.cifra_qr_switch_summary_on);
        cold.addPreference(qr);
        final Preference howTo = action(R.string.cifra_cold_howto_title,
                R.string.cifra_cold_howto_summary);
        howTo.setOnPreferenceClickListener(p -> {
            SecureDialogs.show(new AlertDialog.Builder(getActivity())
                    .setTitle(R.string.cifra_cold_howto_title)
                    .setMessage(getString(R.string.cifra_cold_howto_text,
                            QrCodes.MAX_PLAINTEXT_BYTES))
                    .setPositiveButton(android.R.string.ok, null));
            return true;
        });
        cold.addPreference(howTo);
        final Preference write = action(R.string.cifra_cold_write_title,
                R.string.cifra_cold_write_summary);
        write.setOnPreferenceClickListener(p -> {
            mOpeningOwnScreen = true;
            startActivity(new Intent(getActivity(), ColdWriteActivity.class));
            return true;
        });
        cold.addPreference(write);
    }

    private void addSecurityCategory(final PreferenceScreen screen) {
        final PreferenceCategory security = category(screen, R.string.cifra_security);
        security.addPreference(info(getString(R.string.cifra_about_title),
                getString(R.string.cifra_about_summary)));
        security.addPreference(keystorePreference());
        final SwitchPreference screenReader = new SwitchPreference(getActivity());
        screenReader.setKey(SecureKeyboard.PREF_SCREEN_READER);
        screenReader.setDefaultValue(false);
        screenReader.setTitle(R.string.cifra_screen_reader_title);
        screenReader.setSummaryOff(R.string.cifra_screen_reader_summary_off);
        screenReader.setSummaryOn(Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
                ? R.string.cifra_screen_reader_summary_on
                : R.string.cifra_screen_reader_summary_on_legacy);
        security.addPreference(screenReader);
        final ListPreference reread = new ListPreference(getActivity());
        reread.setKey(SecureKeyboard.PREF_REREAD_HOURS);
        reread.setTitle(R.string.cifra_reread_title);
        reread.setDialogTitle(R.string.cifra_reread_title);
        reread.setEntries(R.array.cifra_reread_entries);
        reread.setEntryValues(R.array.cifra_reread_values);
        reread.setDefaultValue("0");
        reread.setOnPreferenceChangeListener((p, value) -> {
            final int index = reread.findIndexOfValue((String) value);
            p.setSummary(rereadSummary(reread, index));
            return true;
        });
        security.addPreference(reread);
        reread.setSummary(rereadSummary(reread, reread.findIndexOfValue(reread.getValue())));
        security.addPreference(wipeAction());
    }

    private String rereadSummary(final ListPreference preference, final int index) {
        final CharSequence[] entries = preference.getEntries();
        final CharSequence entry = entries[index >= 0 ? index : 0];
        return getString(R.string.cifra_reread_summary, entry);
    }

    private Preference keystorePreference() {
        final Preference preference = new Preference(getActivity());
        preference.setTitle(R.string.cifra_keystore_title);
        final KeystoreCapabilities caps = KeystoreCapabilities.load(getActivity());
        if (caps == null) {
            preference.setSummary(R.string.cifra_keystore_measuring);
            KeystoreCapabilities.ensureProbed(getActivity(), result -> {
                if (getActivity() == null) {
                    return;
                }
                if (mUnlocked) {
                    rebuild();
                } else {
                    showLocked();
                }
            });
        } else {
            preference.setSummary(keystoreSummary(caps));
            preference.setOnPreferenceClickListener(p -> {
                showKeystoreDetails(caps);
                return true;
            });
        }
        return preference;
    }

    private String keystoreSummary(final KeystoreCapabilities caps) {
        if (caps.bestForX25519().isHardware()) {
            return getString(R.string.cifra_keystore_summary_native,
                    whereLabel(caps.bestForX25519()));
        }
        if (caps.bestForP256().isHardware()) {
            return getString(R.string.cifra_keystore_summary_p256_only,
                    whereLabel(caps.bestForP256()));
        }
        return getString(R.string.cifra_keystore_summary_wrapped, whereLabel(bestAes(caps)));
    }

    private void showKeystoreDetails(final KeystoreCapabilities caps) {
        final String keyMint = caps.mKeyMintVersion > 0
                ? String.valueOf(caps.mKeyMintVersion) : getString(R.string.cifra_keystore_unknown);
        final String strongBox = caps.mStrongBoxFeature
                ? getString(R.string.cifra_keystore_present) : getString(R.string.cifra_keystore_absent);
        final String details = getString(R.string.cifra_keystore_details, keyMint, strongBox,
                whereLabel(bestAes(caps)), whereLabel(caps.mX25519Generated),
                whereLabel(caps.mX25519Imported),
                whereLabel(caps.mP256GeneratedStrongBox.isHardware()
                        ? caps.mP256GeneratedStrongBox : caps.mP256GeneratedTee),
                whereLabel(caps.bestForP256()));
        SecureDialogs.show(new AlertDialog.Builder(getActivity())
                .setTitle(R.string.cifra_keystore_title)
                .setMessage(details)
                .setNeutralButton(R.string.cifra_keystore_retest, (d, w) ->
                        KeystoreCapabilities.probeAsync(getActivity(), result -> {
                            if (getActivity() == null) {
                                return;
                            }
                            if (mUnlocked) {
                                rebuild();
                            } else {
                                showLocked();
                            }
                            showKeystoreDetails(result);
                        }))
                .setPositiveButton(android.R.string.ok, null));
    }

    private static KeystoreCapabilities.Where bestAes(final KeystoreCapabilities caps) {
        return caps.mAesStrongBox.isHardware() ? caps.mAesStrongBox : caps.mAesTee;
    }

    private String whereLabel(final KeystoreCapabilities.Where where) {
        switch (where) {
            case STRONGBOX:
                return getString(R.string.cifra_where_strongbox);
            case TEE:
                return getString(R.string.cifra_where_tee);
            case SECURE_HARDWARE:
                return getString(R.string.cifra_where_hardware);
            case SOFTWARE:
                return getString(R.string.cifra_where_software);
            default:
                return getString(R.string.cifra_where_unavailable);
        }
    }

    private Preference wipeAction() {
        final Preference wipe = action(R.string.cifra_wipe, R.string.cifra_wipe_summary);
        wipe.setOnPreferenceClickListener(p -> {
            SecureDialogs.show(new AlertDialog.Builder(getActivity())
                    .setMessage(R.string.cifra_wipe_confirm)
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(R.string.cifra_delete, (d, w) -> {
                        mStore.wipeEverything();
                        toast(R.string.cifra_wiped);
                        if (mUnlocked) {
                            rebuild();
                        } else {
                            showLocked();
                        }
                    }));
            return true;
        });
        return wipe;
    }

    private void showIdentity(final Vault.Identity identity) {
        SecureDialogs.show(new AlertDialog.Builder(getActivity())
                .setTitle(identity.mName)
                .setView(keyInfoView(identity.getEncodedPublicKey(), identity.getFingerprint(),
                        getString(R.string.cifra_qr_key_hint), true))
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
                        getString(R.string.cifra_verify_hint, contact.mName), false))
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

        final boolean hasCamera = getActivity().getPackageManager().hasSystemFeature(
                PackageManager.FEATURE_CAMERA_ANY);
        final AlertDialog.Builder builder = new AlertDialog.Builder(getActivity())
                .setTitle(R.string.cifra_add_contact)
                .setView(view)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.cifra_add_contact, null);
        if (hasCamera) {
            builder.setNeutralButton(R.string.cifra_scan_qr, null);
        }
        final AlertDialog dialog = SecureDialogs.show(builder);
        if (hasCamera) {
            // Set after showing, so the button does not close the dialog.
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> {
                mOpeningOwnScreen = true;
                QrScanActivity.request(getActivity(), QrScanActivity.KIND_KEY, false, content -> {
                    final byte[] publicKey = QrCodes.publicKey(content);
                    if (publicKey != null && dialog.isShowing()) {
                        key.setText(CifraCrypto.encodePublicKey(publicKey));
                    }
                });
            });
        }
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

    /** @param showQr shows the key as a QR code, for the other person to scan. */
    private View keyInfoView(final String encodedKey, final String fingerprint,
            final String hint, final boolean showQr) {
        final View view = LayoutInflater.from(getActivity())
                .inflate(R.layout.cifra_dialog_key_info, null);
        if (showQr) {
            final ImageView qr = view.findViewById(R.id.cifra_key_qr);
            qr.setImageDrawable(QrViews.drawable(getResources(),
                    QrCodes.encodeText(encodedKey)));
            qr.setVisibility(View.VISIBLE);
        }
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
        mOpeningOwnScreen = true;
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
            case AUTH_REQUIRED:
                return getString(R.string.cifra_error_auth_expired);
            case NO_LOCK_SCREEN:
                return getString(R.string.cifra_no_lock_screen);
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
