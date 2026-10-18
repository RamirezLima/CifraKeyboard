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

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.text.Layout;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.util.Log;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.inputmethod.EditorInfo;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import rkr.simplekeyboard.inputmethod.R;
import rkr.simplekeyboard.inputmethod.compat.PreferenceManagerCompat;
import rkr.simplekeyboard.inputmethod.event.Event;
import rkr.simplekeyboard.inputmethod.latin.LatinIME;
import rkr.simplekeyboard.inputmethod.latin.common.Constants;
import rkr.simplekeyboard.inputmethod.latin.settings.Settings;
import rkr.simplekeyboard.inputmethod.latin.settings.SettingsValues;

/**
 * Secure mode of the keyboard.
 *
 * While a secure session is open every key goes to a draft kept inside the keyboard instead of
 * the app. Only after the user taps "Encrypt" and approves the result is the ciphertext committed
 * to the app. Encrypted messages found in the clipboard are decrypted and shown only in the
 * keyboard window, which is protected by FLAG_SECURE (see {@link LatinIME#onCreate()}).
 */
public final class SecureKeyboard implements ClipboardManager.OnPrimaryClipChangedListener {
    private static final String TAG = SecureKeyboard.class.getSimpleName();
    private static final long DRAFT_WIPE_DELAY_MILLIS = TimeUnit.MINUTES.toMillis(5);
    private static final int MAX_DRAFT_CHARS = CifraCrypto.MAX_PLAINTEXT_BYTES / 4;

    /** Lets screen readers into secure mode. Off by default. */
    public static final String PREF_SCREEN_READER = "pref_cifra_screen_reader";

    public static boolean readScreenReaderAllowed(final SharedPreferences prefs) {
        return prefs.getBoolean(PREF_SCREEN_READER, false);
    }

    /**
     * Hides a text from every accessibility service, accessibility tools included: marking views
     * as not important or as sensitive still lets some services read them.
     */
    private static final View.AccessibilityDelegate HIDE_TEXT = new View.AccessibilityDelegate() {
        @Override
        public void onInitializeAccessibilityNodeInfo(final View host,
                final AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(host, info);
            info.setText(null);
            info.setContentDescription(null);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                info.setHintText(null);
            }
        }

        @Override
        public boolean dispatchPopulateAccessibilityEvent(final View host,
                final AccessibilityEvent event) {
            return false;
        }

        @Override
        public void onPopulateAccessibilityEvent(final View host,
                final AccessibilityEvent event) {
            // Nothing: the event must not carry the text.
        }

        @Override
        public void sendAccessibilityEvent(final View host, final int eventType) {
            // Dropped: text change events carry the text.
        }

        @Override
        public void sendAccessibilityEventUnchecked(final View host,
                final AccessibilityEvent event) {
            // Dropped.
        }
    };

    private enum Mode {
        IDLE,
        COMPOSE,
        // Overlays covering the keys:
        MENU,
        PICK_RECIPIENT,
        PICK_SENDER,
        PICK_IDENTITY,
        BUSY,
        PREVIEW,
        READ,
        MESSAGE,
    }

    private final LatinIME mIme;
    private final VaultStore mStore;
    private final ClipboardManager mClipboard;
    private final Handler mHandler = new Handler(Looper.getMainLooper());
    private final Runnable mWipeDraftRunnable = this::wipeDraft;

    private View mFrame;
    private View mBar;
    private View mKeyboardView;
    private ImageView mLockButton;
    private TextView mStatus;
    private TextView mClipboardButton;
    private TextView mEncryptButton;
    private TextView mComposeText;
    private View mOverlay;
    private TextView mOverlayTitle;
    private TextView mOverlaySubtitle;
    private TextView mOverlayBody;
    private ScrollView mOverlayScroll;
    private LinearLayout mOverlayList;
    private View mOverlayButtons;
    private TextView mOverlayPrimary;
    private TextView mOverlaySecondary;

    private Mode mMode = Mode.IDLE;
    /** True while the keys are captured into {@link #mDraft}, including under an overlay. */
    private boolean mSecureSession;
    private final StringBuilder mDraft = new StringBuilder();
    private String mRecipientId;
    private String mSenderId;
    private String mPendingCiphertext;
    private boolean mClipboardHasMessage;
    private boolean mScreenReaderAllowed;
    /** Invalidates the results of background tasks the user walked away from. */
    private int mTaskGeneration;

    public SecureKeyboard(final LatinIME ime) {
        mIme = ime;
        mStore = VaultStore.getInstance(ime);
        mClipboard = (ClipboardManager) ime.getSystemService(Context.CLIPBOARD_SERVICE);
    }

    public void onCreate() {
        if (mClipboard != null) {
            mClipboard.addPrimaryClipChangedListener(this);
        }
    }

    public void onDestroy() {
        if (mClipboard != null) {
            mClipboard.removePrimaryClipChangedListener(this);
        }
        mHandler.removeCallbacksAndMessages(null);
        wipeDraft();
        mSecureSession = false;
    }

    /**
     * Binds to a freshly inflated input view. Called every time the keyboard view is recreated
     * (e.g. on a theme change), so the state survives in this object.
     */
    public void bindViews(final View inputView) {
        mFrame = inputView.findViewById(R.id.keyboard_frame);
        mBar = inputView.findViewById(R.id.cifra_bar);
        mKeyboardView = inputView.findViewById(R.id.keyboard_view);
        mLockButton = inputView.findViewById(R.id.cifra_lock_button);
        mStatus = inputView.findViewById(R.id.cifra_status);
        mClipboardButton = inputView.findViewById(R.id.cifra_clipboard_button);
        mEncryptButton = inputView.findViewById(R.id.cifra_encrypt_button);
        mComposeText = inputView.findViewById(R.id.cifra_compose_text);
        mOverlay = inputView.findViewById(R.id.cifra_overlay);
        mOverlayTitle = inputView.findViewById(R.id.cifra_overlay_title);
        mOverlaySubtitle = inputView.findViewById(R.id.cifra_overlay_subtitle);
        mOverlayBody = inputView.findViewById(R.id.cifra_overlay_body);
        mOverlayScroll = inputView.findViewById(R.id.cifra_overlay_scroll);
        mOverlayList = inputView.findViewById(R.id.cifra_overlay_list);
        mOverlayButtons = inputView.findViewById(R.id.cifra_overlay_buttons);
        mOverlayPrimary = inputView.findViewById(R.id.cifra_overlay_primary);
        mOverlaySecondary = inputView.findViewById(R.id.cifra_overlay_secondary);

        mLockButton.setOnClickListener(v -> onLockPressed());
        mClipboardButton.setOnClickListener(v -> onClipboardPressed());
        mEncryptButton.setOnClickListener(v -> onEncryptPressed());
        inputView.findViewById(R.id.cifra_overlay_close).setOnClickListener(v -> closeOverlay());
        mKeyboardView.addOnLayoutChangeListener(
                (v, left, top, right, bottom, oldLeft, oldTop, oldRight, oldBottom) -> {
                    if (bottom - top != oldBottom - oldTop) {
                        mHandler.post(this::syncOverlayHeight);
                    }
                });

        applyAccessibilityMode();

        // The overlay content is not kept across view recreation.
        if (mMode != Mode.IDLE && mMode != Mode.COMPOSE) {
            closeOverlay();
        }
        render();
    }

    public void onStartInputView(final EditorInfo editorInfo) {
        mHandler.removeCallbacks(mWipeDraftRunnable);
        applyAccessibilityMode();
        refreshClipboardState();
        render();
    }

    public void onWindowHidden() {
        switch (mMode) {
            case IDLE:
            case COMPOSE:
                break;
            default:
                // Never leave a decrypted message on screen, nor a stale pending action.
                closeOverlay();
                break;
        }
        if (mSecureSession && mDraft.length() > 0) {
            mHandler.removeCallbacks(mWipeDraftRunnable);
            mHandler.postDelayed(mWipeDraftRunnable, DRAFT_WIPE_DELAY_MILLIS);
        }
    }

    /**
     * @return true when the keys must go to the secure draft instead of the app.
     */
    public boolean isCapturingInput() {
        return mSecureSession;
    }

    /**
     * Functional keys that keep their normal behavior in secure mode, because they do not touch
     * the app's text.
     */
    public static boolean passesThrough(final Event event) {
        return event.isFunctionalKeyEvent()
                && (event.mKeyCode == Constants.CODE_SETTINGS
                        || event.mKeyCode == Constants.CODE_LANGUAGE_SWITCH);
    }

    public void onEvent(final Event event) {
        if (mMode != Mode.COMPOSE) {
            return; // The keys are covered by an overlay.
        }
        if (event.isFunctionalKeyEvent()) {
            switch (event.mKeyCode) {
                case Constants.CODE_DELETE:
                    deleteLastCodePoint();
                    break;
                case Constants.CODE_PASTE:
                    appendText(readClipboardText());
                    break;
                case Constants.CODE_SHIFT_ENTER:
                    appendText("\n");
                    break;
                default:
                    // Shift, caps lock and layout switches only change the keyboard itself.
                    return;
            }
        } else if (event.mCodePoint > 0) {
            appendText(new String(Character.toChars(event.mCodePoint)));
        }
        renderDraft();
    }

    /**
     * Keys from a physical keyboard reach the IME before the app. In secure mode the ones that
     * produce text are captured, also while an overlay is shown, so they can never leak to the
     * app. Shortcuts with Ctrl or Meta pass through.
     *
     * @return true if the key was consumed.
     */
    public boolean onHardwareKeyDown(final KeyEvent event) {
        if (!isHardwareTextKey(event)) {
            return false;
        }
        if (mMode != Mode.COMPOSE) {
            return true;
        }
        switch (event.getKeyCode()) {
            case KeyEvent.KEYCODE_DEL:
                deleteLastCodePoint();
                break;
            case KeyEvent.KEYCODE_ENTER:
            case KeyEvent.KEYCODE_NUMPAD_ENTER:
                appendText("\n");
                break;
            default:
                final int unicode = event.getUnicodeChar();
                if ((unicode & KeyCharacterMap.COMBINING_ACCENT) == 0) {
                    appendText(new String(Character.toChars(unicode)));
                }
                break;
        }
        renderDraft();
        return true;
    }

    public static boolean isHardwareTextKey(final KeyEvent event) {
        if (event.isCtrlPressed() || event.isMetaPressed()) {
            return false;
        }
        switch (event.getKeyCode()) {
            case KeyEvent.KEYCODE_DEL:
            case KeyEvent.KEYCODE_ENTER:
            case KeyEvent.KEYCODE_NUMPAD_ENTER:
                return true;
            default:
                return event.getUnicodeChar() != 0;
        }
    }

    public void onTextInput(final String text) {
        if (mMode != Mode.COMPOSE) {
            return;
        }
        appendText(text);
        renderDraft();
    }

    public int getCurrentAutoCapsState(final SettingsValues settingsValues) {
        if (!settingsValues.mAutoCap) {
            return Constants.TextUtils.CAP_MODE_OFF;
        }
        return TextUtils.getCapsMode(mDraft, mDraft.length(), TextUtils.CAP_MODE_SENTENCES);
    }

    public boolean handleBack() {
        if (mMode == Mode.IDLE || mMode == Mode.COMPOSE) {
            return false;
        }
        closeOverlay();
        return true;
    }

    @Override
    public void onPrimaryClipChanged() {
        refreshClipboardState();
    }

    // Draft

    private void appendText(final CharSequence text) {
        if (text == null) {
            return;
        }
        final int room = MAX_DRAFT_CHARS - mDraft.length();
        if (room <= 0) {
            return;
        }
        mDraft.append(text, 0, Math.min(room, text.length()));
    }

    private void deleteLastCodePoint() {
        final int length = mDraft.length();
        if (length == 0) {
            return;
        }
        final int codePoint = mDraft.codePointBefore(length);
        final int newLength = length - Character.charCount(codePoint);
        mDraft.setCharAt(length - 1, '\0');
        mDraft.setLength(newLength);
    }

    private void wipeDraft() {
        for (int i = 0; i < mDraft.length(); i++) {
            mDraft.setCharAt(i, '\0');
        }
        mDraft.setLength(0);
        renderDraft();
    }

    private void startSession(final String recipientId, final String senderId) {
        mRecipientId = recipientId;
        mSenderId = senderId;
        mSecureSession = true;
        mMode = Mode.COMPOSE;
        hideOverlayViews();
        render();
        mIme.onSecureInputChanged();
    }

    private void endSession() {
        wipeDraft();
        mSecureSession = false;
        mRecipientId = null;
        mPendingCiphertext = null;
        mMode = Mode.IDLE;
        hideOverlayViews();
        render();
        mIme.onSecureInputChanged();
    }

    // Bar actions

    private void onLockPressed() {
        if (!mStore.isStorageAvailable()) {
            showMessage(mIme.getString(R.string.cifra_secure_menu),
                    mIme.getString(R.string.cifra_error_locked));
            return;
        }
        if (mSecureSession) {
            showSessionMenu();
        } else {
            showRecipientPicker();
        }
    }

    private void showSessionMenu() {
        final Vault vault = loadVault();
        if (vault == null) {
            return;
        }
        final Vault.Contact recipient = vault.findContact(mRecipientId);
        showOverlay(Mode.MENU, mIme.getString(R.string.cifra_secure_menu),
                recipient == null ? null : mIme.getString(R.string.cifra_bar_to, recipient.mName));
        addRow(mIme.getString(R.string.cifra_change_recipient), null, this::showRecipientPicker);
        if (vault.getIdentities().size() > 1) {
            addRow(mIme.getString(R.string.cifra_change_sender), senderName(vault),
                    this::showSenderPicker);
        }
        addRow(mIme.getString(R.string.cifra_manage_keys), null, this::openSettings);
        addRow(mIme.getString(R.string.cifra_exit_secure), null, this::endSession);
    }

    private void showRecipientPicker() {
        final Vault vault = loadVault();
        if (vault == null) {
            return;
        }
        if (vault.getIdentities().isEmpty()) {
            showSetupNeeded(mIme.getString(R.string.cifra_need_identity));
            return;
        }
        if (vault.getContacts().isEmpty()) {
            showSetupNeeded(mIme.getString(R.string.cifra_need_contact));
            return;
        }
        showOverlay(Mode.PICK_RECIPIENT, mIme.getString(R.string.cifra_pick_recipient),
                mIme.getString(R.string.cifra_sending_as, senderName(vault)));
        for (final Vault.Contact contact : vault.getContacts()) {
            addRow(contactLabel(contact), contact.getFingerprint(),
                    () -> startSession(contact.mId, mSenderId));
        }
        if (vault.getIdentities().size() > 1) {
            addRow(mIme.getString(R.string.cifra_change_sender), null, this::showSenderPicker);
        }
        addRow(mIme.getString(R.string.cifra_manage_keys), null, this::openSettings);
    }

    private void showSenderPicker() {
        final Vault vault = loadVault();
        if (vault == null) {
            return;
        }
        showOverlay(Mode.PICK_SENDER, mIme.getString(R.string.cifra_pick_sender), null);
        for (final Vault.Identity identity : vault.getIdentities()) {
            addRow(identity.mName, identity.getFingerprint(), () -> {
                mSenderId = identity.mId;
                if (mSecureSession) {
                    closeOverlay();
                } else {
                    showRecipientPicker();
                }
            });
        }
    }

    private void onEncryptPressed() {
        if (mMode != Mode.COMPOSE) {
            return;
        }
        if (mDraft.length() == 0) {
            showMessage(mIme.getString(R.string.cifra_bar_encrypt),
                    mIme.getString(R.string.cifra_empty_message));
            return;
        }
        final Vault vault = loadVault();
        if (vault == null) {
            return;
        }
        final Vault.Contact recipient = vault.findContact(mRecipientId);
        final Vault.Identity sender = resolveSender(vault);
        if (recipient == null || sender == null) {
            showRecipientPicker();
            return;
        }
        final String plaintext = mDraft.toString();
        if (plaintext.getBytes(StandardCharsets.UTF_8).length > CifraCrypto.MAX_PLAINTEXT_BYTES) {
            showMessage(mIme.getString(R.string.cifra_bar_encrypt),
                    mIme.getString(R.string.cifra_message_too_long));
            return;
        }
        final int generation = showBusy(mIme.getString(R.string.cifra_encrypting));
        VaultStore.runAsync(() -> mStore.encrypt(plaintext, recipient, sender),
                (armored, error) -> {
                    if (generation != mTaskGeneration) {
                        return;
                    }
                    if (error != null) {
                        showError(error);
                        return;
                    }
                    mPendingCiphertext = armored;
                    showPreview(recipient);
                });
    }

    private void showPreview(final Vault.Contact recipient) {
        showOverlay(Mode.PREVIEW, mIme.getString(R.string.cifra_preview_title, recipient.mName),
                mIme.getString(R.string.cifra_preview_info, recipient.mName));
        setBody(mPendingCiphertext, true);
        setButtons(mIme.getString(R.string.cifra_edit), () -> {
            mPendingCiphertext = null;
            closeOverlay();
        }, mIme.getString(R.string.cifra_insert), this::insertCiphertext);
    }

    private void insertCiphertext() {
        if (mPendingCiphertext == null) {
            return;
        }
        String text = mPendingCiphertext;
        final EditorInfo editorInfo = mIme.getCurrentInputEditorInfo();
        if (editorInfo != null && (editorInfo.inputType & InputType.TYPE_MASK_CLASS)
                == InputType.TYPE_CLASS_TEXT
                && (editorInfo.inputType & InputType.TYPE_TEXT_FLAG_MULTI_LINE) == 0) {
            // Single line fields may drop line breaks; the reader tolerates spaces instead.
            text = text.replace('\n', ' ');
        }
        mIme.commitSecureText(text);
        mPendingCiphertext = null;
        wipeDraft();
        // Stay in secure mode with the same recipient: fail closed for the next message.
        closeOverlay();
    }

    private void onClipboardPressed() {
        final byte[] wire = CifraCrypto.dearmor(readClipboardText());
        if (wire == null) {
            refreshClipboardState();
            showMessage(mIme.getString(R.string.cifra_bar_clipboard_status),
                    mIme.getString(R.string.cifra_clipboard_invalid));
            return;
        }
        final Vault vault = loadVault();
        if (vault == null) {
            return;
        }
        final List<Vault.Identity> identities = vault.getIdentities();
        if (identities.isEmpty()) {
            showSetupNeeded(mIme.getString(R.string.cifra_need_identity));
            return;
        }
        if (identities.size() == 1) {
            decrypt(wire, identities);
            return;
        }
        showOverlay(Mode.PICK_IDENTITY, mIme.getString(R.string.cifra_pick_identity), null);
        for (final Vault.Identity identity : identities) {
            addRow(identity.mName, identity.getFingerprint(),
                    () -> decrypt(wire, Collections.singletonList(identity)));
        }
        addRow(mIme.getString(R.string.cifra_try_all), null, () -> decrypt(wire, identities));
    }

    private void decrypt(final byte[] wire, final List<Vault.Identity> candidates) {
        final int generation = showBusy(mIme.getString(R.string.cifra_decrypting));
        VaultStore.runAsync(() -> {
            for (final Vault.Identity identity : candidates) {
                final VaultStore.DecryptResult result = mStore.decrypt(wire, identity);
                if (result != null) {
                    return result;
                }
            }
            return null;
        }, (result, error) -> {
            if (generation != mTaskGeneration) {
                return;
            }
            if (error != null) {
                showError(error);
            } else if (result == null) {
                showMessage(mIme.getString(R.string.cifra_bar_clipboard_status),
                        mIme.getString(R.string.cifra_decrypt_failed));
            } else {
                showRead(result);
            }
        });
    }

    private void showRead(final VaultStore.DecryptResult result) {
        final String title;
        if (result.mSenderContact != null) {
            title = mIme.getString(result.mSenderContact.mVerified ? R.string.cifra_from
                    : R.string.cifra_from_unverified, result.mSenderContact.mName);
        } else {
            title = mIme.getString(R.string.cifra_from_self, result.mSenderIdentity.mName);
        }
        showOverlay(Mode.READ, title,
                mIme.getString(R.string.cifra_read_info, result.mRecipient.mName));
        setBody(result.mPlaintext, false);
        final Vault.Contact sender = result.mSenderContact;
        if (sender != null) {
            setButtons(mIme.getString(R.string.cifra_close), this::closeOverlay,
                    mIme.getString(R.string.cifra_reply),
                    () -> startSession(sender.mId, result.mRecipient.mId));
        } else {
            setButtons(null, null, mIme.getString(R.string.cifra_close), this::closeOverlay);
        }
    }

    private void showSetupNeeded(final String message) {
        showMessage(mIme.getString(R.string.cifra_secure_menu), message);
        setButtons(mIme.getString(R.string.cifra_close), this::closeOverlay,
                mIme.getString(R.string.cifra_manage_keys), this::openSettings);
    }

    private void showError(final VaultStore.VaultException error) {
        final int message;
        switch (error.mReason) {
            case DEVICE_LOCKED:
                message = R.string.cifra_error_locked;
                break;
            case KEY_LOST:
                message = R.string.cifra_error_key_lost;
                break;
            default:
                message = R.string.cifra_error_generic;
                break;
        }
        showMessage(mIme.getString(R.string.cifra_secure_menu), mIme.getString(message));
    }

    private void openSettings() {
        closeOverlay();
        mIme.launchCryptoSettings();
    }

    // Vault helpers

    private Vault loadVault() {
        try {
            return mStore.getVault();
        } catch (VaultStore.VaultException e) {
            showError(e);
            return null;
        }
    }

    private Vault.Identity resolveSender(final Vault vault) {
        final Vault.Identity chosen = mSenderId == null ? null : vault.findIdentity(mSenderId);
        return chosen != null ? chosen : vault.getDefaultIdentity();
    }

    private String senderName(final Vault vault) {
        final Vault.Identity sender = resolveSender(vault);
        return sender == null ? "" : sender.mName;
    }

    private String contactLabel(final Vault.Contact contact) {
        return contact.mVerified ? contact.mName + "  ✓" : contact.mName;
    }

    // Clipboard

    private CharSequence readClipboardText() {
        if (mClipboard == null) {
            return null;
        }
        try {
            final ClipData clip = mClipboard.getPrimaryClip();
            if (clip == null || clip.getItemCount() == 0) {
                return null;
            }
            return clip.getItemAt(0).getText();
        } catch (SecurityException e) {
            // Only the focused app and the current IME may read the clipboard.
            Log.w(TAG, "Clipboard not readable now");
            return null;
        }
    }

    private void refreshClipboardState() {
        final boolean hasMessage = CifraCrypto.containsArmoredMessage(readClipboardText());
        if (hasMessage != mClipboardHasMessage) {
            mClipboardHasMessage = hasMessage;
            render();
        }
    }

    // Overlay

    private int showBusy(final String title) {
        showOverlay(Mode.BUSY, title, null);
        mOverlay.findViewById(R.id.cifra_overlay_close).setVisibility(View.INVISIBLE);
        return mTaskGeneration;
    }

    private void showMessage(final String title, final String message) {
        showOverlay(Mode.MESSAGE, title, null);
        setBody(message, false);
        setButtons(null, null, mIme.getString(android.R.string.ok), this::closeOverlay);
    }

    private void showOverlay(final Mode mode, final CharSequence title,
            final CharSequence subtitle) {
        mTaskGeneration++;
        mMode = mode;
        if (mOverlay == null) {
            return;
        }
        mOverlayTitle.setText(title);
        mOverlaySubtitle.setText(subtitle);
        mOverlaySubtitle.setVisibility(TextUtils.isEmpty(subtitle) ? View.GONE : View.VISIBLE);
        clearBody();
        mOverlayList.removeAllViews();
        mOverlayButtons.setVisibility(View.GONE);
        mOverlay.findViewById(R.id.cifra_overlay_close).setVisibility(View.VISIBLE);
        mOverlayScroll.scrollTo(0, 0);
        syncOverlayHeight();
        mOverlay.setVisibility(View.VISIBLE);
        render();
    }

    private void closeOverlay() {
        mTaskGeneration++;
        mMode = mSecureSession ? Mode.COMPOSE : Mode.IDLE;
        hideOverlayViews();
        render();
    }

    private void hideOverlayViews() {
        if (mOverlay == null) {
            return;
        }
        clearBody();
        mOverlayList.removeAllViews();
        mOverlay.setVisibility(View.GONE);
    }

    private void clearBody() {
        mOverlayBody.setText(null);
        mOverlayBody.setVisibility(View.GONE);
    }

    private void setBody(final CharSequence text, final boolean monospace) {
        mOverlayBody.setTypeface(monospace ? Typeface.MONOSPACE : Typeface.DEFAULT);
        mOverlayBody.setTextSize(monospace ? 12 : 16);
        mOverlayBody.setText(text);
        mOverlayBody.setVisibility(View.VISIBLE);
    }

    private void addRow(final CharSequence title, final CharSequence detail,
            final Runnable action) {
        final TextView row = (TextView) LayoutInflater.from(mOverlayList.getContext())
                .inflate(R.layout.cifra_overlay_row, mOverlayList, false);
        if (TextUtils.isEmpty(detail)) {
            row.setText(title);
        } else {
            final SpannableStringBuilder text = new SpannableStringBuilder(title);
            final int start = text.length();
            text.append('\n').append(detail);
            text.setSpan(new RelativeSizeSpan(0.8f), start, text.length(),
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            row.setText(text);
        }
        row.setOnClickListener(v -> action.run());
        protectText(row);
        mOverlayList.addView(row);
    }

    private void setButtons(final CharSequence secondary, final Runnable secondaryAction,
            final CharSequence primary, final Runnable primaryAction) {
        mOverlayButtons.setVisibility(View.VISIBLE);
        mOverlaySecondary.setVisibility(secondary == null ? View.GONE : View.VISIBLE);
        mOverlaySecondary.setText(secondary);
        mOverlaySecondary.setOnClickListener(secondaryAction == null ? null
                : v -> secondaryAction.run());
        mOverlayPrimary.setText(primary);
        mOverlayPrimary.setOnClickListener(v -> primaryAction.run());
    }

    private void syncOverlayHeight() {
        if (mOverlay == null || mKeyboardView == null || mKeyboardView.getHeight() == 0) {
            return;
        }
        final ViewGroup.LayoutParams params = mOverlay.getLayoutParams();
        if (params.height != mKeyboardView.getHeight()) {
            params.height = mKeyboardView.getHeight();
            mOverlay.setLayoutParams(params);
        }
        final int bottom = mIme.getResources().getDimensionPixelSize(R.dimen.cifra_bar_height) / 7
                + mKeyboardView.getPaddingBottom();
        mOverlay.setPadding(mOverlay.getPaddingLeft(), mOverlay.getPaddingTop(),
                mOverlay.getPaddingRight(), bottom);
    }

    // Accessibility

    /**
     * Drafts, decrypted messages and contact names are a common target of spyware that abuses
     * accessibility. By default they are hidden from every accessibility service; the user can
     * let screen readers in. From Android 14 the secure views are also marked as sensitive, so
     * even then only services the system knows as accessibility tools can read them.
     */
    private void applyAccessibilityMode() {
        if (mFrame == null) {
            return;
        }
        mScreenReaderAllowed = readScreenReaderAllowed(
                PreferenceManagerCompat.getDeviceSharedPreferences(mIme));
        for (final View container : new View[] { mBar, mComposeText, mOverlay }) {
            container.setImportantForAccessibility(mScreenReaderAllowed
                    ? View.IMPORTANT_FOR_ACCESSIBILITY_AUTO
                    : View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                container.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES);
            }
        }
        for (final TextView text : new TextView[] { mStatus, mComposeText, mOverlayTitle,
                mOverlaySubtitle, mOverlayBody }) {
            protectText(text);
        }
        for (int i = 0; i < mOverlayList.getChildCount(); i++) {
            protectText((TextView) mOverlayList.getChildAt(i));
        }
    }

    private void protectText(final TextView view) {
        view.setAccessibilityDelegate(mScreenReaderAllowed ? null : HIDE_TEXT);
    }

    // Rendering

    private void render() {
        if (mFrame == null) {
            return;
        }
        final SharedPreferences prefs = PreferenceManagerCompat.getDeviceSharedPreferences(mIme);
        final int background = Settings.readKeyboardColor(prefs, mIme);
        mFrame.setBackgroundColor(background);
        mOverlay.setBackgroundColor(background);

        final boolean available = mStore.isStorageAvailable();
        mLockButton.setImageResource(mSecureSession ? R.drawable.ic_cifra_lock
                : R.drawable.ic_cifra_lock_open);
        if (mSecureSession) {
            mLockButton.setBackgroundResource(R.drawable.cifra_accent_background);
            mLockButton.setColorFilter(mIme.getColor(R.color.cifra_on_accent));
        } else {
            mLockButton.setBackgroundResource(R.drawable.cifra_button_background);
            mLockButton.setColorFilter(mStatus.getCurrentTextColor());
        }

        final boolean showClipboard = available && mClipboardHasMessage
                && mMode != Mode.READ && mMode != Mode.BUSY && mMode != Mode.PICK_IDENTITY;
        mClipboardButton.setVisibility(showClipboard ? View.VISIBLE : View.GONE);
        mEncryptButton.setVisibility(mMode == Mode.COMPOSE ? View.VISIBLE : View.GONE);

        final CharSequence status;
        if (!available) {
            status = mIme.getString(R.string.cifra_bar_unavailable);
        } else if (mSecureSession) {
            status = mIme.getString(R.string.cifra_bar_to, recipientName());
        } else if (mClipboardHasMessage) {
            status = mIme.getString(R.string.cifra_bar_clipboard_status);
        } else {
            status = mIme.getString(R.string.cifra_bar_idle);
        }
        mStatus.setText(status);
        renderDraft();
    }

    private void renderDraft() {
        if (mComposeText == null) {
            return;
        }
        if (mMode != Mode.COMPOSE) {
            mComposeText.setText(null);
            mComposeText.setVisibility(View.GONE);
            return;
        }
        mComposeText.setVisibility(View.VISIBLE);
        mEncryptButton.setEnabled(mDraft.length() > 0);
        if (mDraft.length() == 0) {
            mComposeText.setText(null);
            mComposeText.setHint(mIme.getString(R.string.cifra_compose_hint, recipientName()));
            return;
        }
        final SpannableStringBuilder text = new SpannableStringBuilder(mDraft);
        final int caret = text.length();
        text.append('▏');
        text.setSpan(new ForegroundColorSpan(mIme.getColor(R.color.cifra_accent)), caret,
                text.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        mComposeText.setText(text);
        mComposeText.post(this::scrollDraftToEnd);
    }

    private void scrollDraftToEnd() {
        final Layout layout = mComposeText.getLayout();
        if (layout == null) {
            return;
        }
        final int visible = mComposeText.getHeight() - mComposeText.getTotalPaddingTop()
                - mComposeText.getTotalPaddingBottom();
        final int scroll = layout.getLineTop(layout.getLineCount()) - visible;
        mComposeText.scrollTo(0, Math.max(0, scroll));
    }

    private String recipientName() {
        if (mRecipientId == null) {
            return "";
        }
        try {
            final Vault.Contact contact = mStore.getVault().findContact(mRecipientId);
            return contact == null ? "" : contact.mName;
        } catch (VaultStore.VaultException e) {
            return "";
        }
    }
}
