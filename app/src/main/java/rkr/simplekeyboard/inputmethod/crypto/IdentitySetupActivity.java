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
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.ActionMode;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.MultiAutoCompleteTextView;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;

import rkr.simplekeyboard.inputmethod.R;

/**
 * Creates an identity from English BIP39 words: either words the user already has (restore) or
 * new ones generated here. The words and the passphrase only live in this screen; once the key pair is
 * derived they are dropped and only the Keystore-wrapped secret key is kept.
 */
public final class IdentitySetupActivity extends Activity {
    private final SecureRandom mRandom = new SecureRandom();

    private EditText mName;
    private RadioGroup mMode;
    private View mRestoreSection;
    private View mGenerateSection;
    private MultiAutoCompleteTextView mWords;
    private TextView mWordsStatus;
    private RadioGroup mWordCount;
    private TextView mGeneratedWords;
    private View mGeneratedWarning;
    private View mQuizSection;
    private TextView mQuizPrompt;
    private EditText mQuizFirst;
    private EditText mQuizSecond;
    private EditText mPassphrase;
    private EditText mPassphraseConfirm;
    private View mProgress;
    private Button mSave;

    private Bip39 mWordlist;
    private String[] mGenerated;
    private int[] mQuizPositions;

    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // The words on this screen are the keys: no screenshots, recordings or recents preview.
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.cifra_activity_identity_setup);
        setTitle(R.string.cifra_identity_setup_title);
        final ActionBar actionBar = getActionBar();
        if (actionBar != null) {
            actionBar.setDisplayHomeAsUpEnabled(true);
        }
        final View root = findViewById(R.id.cifra_setup_root);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            root.setOnApplyWindowInsetsListener((view, windowInsets) -> {
                final android.graphics.Insets insets = windowInsets.getInsets(
                        WindowInsets.Type.systemBars() | WindowInsets.Type.ime());
                // The top inset includes the action bar, which overlays the content.
                view.setPadding(insets.left, insets.top, insets.right, insets.bottom);
                return WindowInsets.CONSUMED;
            });
        }

        mName = findViewById(R.id.cifra_identity_name);
        mMode = findViewById(R.id.cifra_mode);
        mRestoreSection = findViewById(R.id.cifra_restore_section);
        mGenerateSection = findViewById(R.id.cifra_generate_section);
        mWords = findViewById(R.id.cifra_words);
        mWordsStatus = findViewById(R.id.cifra_words_status);
        mWordCount = findViewById(R.id.cifra_word_count);
        mGeneratedWords = findViewById(R.id.cifra_generated_words);
        mGeneratedWarning = findViewById(R.id.cifra_generated_warning);
        mQuizSection = findViewById(R.id.cifra_quiz_section);
        mQuizPrompt = findViewById(R.id.cifra_quiz_prompt);
        mQuizFirst = findViewById(R.id.cifra_quiz_first);
        mQuizSecond = findViewById(R.id.cifra_quiz_second);
        mPassphrase = findViewById(R.id.cifra_passphrase);
        mPassphraseConfirm = findViewById(R.id.cifra_passphrase_confirm);
        mProgress = findViewById(R.id.cifra_progress);
        mSave = findViewById(R.id.cifra_save_identity);

        // Never let the words reach the clipboard.
        for (final TextView secret : new TextView[] { mWords, mQuizFirst, mQuizSecond }) {
            secret.setCustomSelectionActionModeCallback(new NoCopyActionMode());
            secret.setLongClickable(false);
        }

        mWordlist = Bip39Wordlist.get(this);
        mWords.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_dropdown_item_1line,
                mWordlist.getWords()));
        mWords.setTokenizer(new SpaceTokenizer());
        mWords.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {}

            @Override
            public void afterTextChanged(final Editable s) {
                updateWordsStatus();
            }
        });

        mMode.setOnCheckedChangeListener((group, checkedId) -> updateMode());
        findViewById(R.id.cifra_generate).setOnClickListener(v -> generate());
        mSave.setOnClickListener(v -> save());
        updateMode();
    }

    @Override
    public boolean onOptionsItemSelected(final MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onDestroy() {
        wipe();
        super.onDestroy();
    }

    private boolean isGenerateMode() {
        return mMode.getCheckedRadioButtonId() == R.id.cifra_mode_generate;
    }

    private void updateMode() {
        final boolean generate = isGenerateMode();
        mRestoreSection.setVisibility(generate ? View.GONE : View.VISIBLE);
        mGenerateSection.setVisibility(generate ? View.VISIBLE : View.GONE);
    }

    private void updateWordsStatus() {
        final String text = mWords.getText().toString();
        final String[] words = Bip39.split(text);
        if (words.length == 0) {
            mWordsStatus.setText(null);
            return;
        }
        // The last word may still be being typed.
        final boolean lastComplete = Character.isWhitespace(text.charAt(text.length() - 1));
        final int checked = lastComplete ? words.length : words.length - 1;
        for (int i = 0; i < checked; i++) {
            if (!mWordlist.contains(words[i])) {
                setStatus(getString(R.string.cifra_status_unknown_word, i + 1, words[i]), false);
                return;
            }
        }
        if (!Bip39.isValidWordCount(words.length)) {
            setStatus(getString(R.string.cifra_status_bad_count, words.length), false);
            return;
        }
        try {
            mWordlist.validate(words);
            setStatus(getString(R.string.cifra_status_valid, words.length), true);
        } catch (Bip39.InvalidMnemonicException e) {
            if (e.mReason == Bip39.InvalidMnemonicException.Reason.UNKNOWN_WORD) {
                setStatus(getString(R.string.cifra_status_unknown_word, e.mWordIndex + 1,
                        words[e.mWordIndex]), false);
            } else {
                setStatus(getString(R.string.cifra_status_bad_checksum), false);
            }
        }
    }

    private void setStatus(final String message, final boolean valid) {
        mWordsStatus.setText(message);
        mWordsStatus.setTextColor(getColor(valid ? R.color.cifra_accent : R.color.cifra_warning));
    }

    private void generate() {
        final int count = mWordCount.getCheckedRadioButtonId() == R.id.cifra_words_12 ? 12 : 24;
        wipeGenerated();
        mGenerated = mWordlist.generate(count, mRandom);

        final StringBuilder text = new StringBuilder();
        final int half = count / 2;
        for (int i = 0; i < half; i++) {
            text.append(String.format(Locale.ROOT, "%2d. %-10s %2d. %s\n", i + 1, mGenerated[i],
                    i + half + 1, mGenerated[i + half]));
        }
        mGeneratedWords.setText(text.toString().trim());
        mGeneratedWords.setVisibility(View.VISIBLE);
        mGeneratedWarning.setVisibility(View.VISIBLE);

        final int first = mRandom.nextInt(count);
        int second;
        do {
            second = mRandom.nextInt(count);
        } while (second == first);
        mQuizPositions = new int[] { Math.min(first, second), Math.max(first, second) };
        mQuizPrompt.setText(getString(R.string.cifra_quiz, mQuizPositions[0] + 1,
                mQuizPositions[1] + 1));
        mQuizFirst.setHint(getString(R.string.cifra_quiz_word_hint, mQuizPositions[0] + 1));
        mQuizSecond.setHint(getString(R.string.cifra_quiz_word_hint, mQuizPositions[1] + 1));
        mQuizFirst.setText(null);
        mQuizSecond.setText(null);
        mQuizSection.setVisibility(View.VISIBLE);
    }

    private void save() {
        final String name = mName.getText().toString().trim();
        if (name.isEmpty()) {
            mName.setError(getString(R.string.cifra_name_required));
            mName.requestFocus();
            return;
        }
        if (!TextUtils.equals(mPassphrase.getText(), mPassphraseConfirm.getText())) {
            mPassphraseConfirm.setError(getString(R.string.cifra_passphrase_mismatch));
            mPassphraseConfirm.requestFocus();
            return;
        }

        final String[] words;
        if (isGenerateMode()) {
            if (mGenerated == null) {
                return;
            }
            final String[] answers = mWordlist.canonicalize(new String[] {
                    mQuizFirst.getText().toString().trim(),
                    mQuizSecond.getText().toString().trim() });
            if (answers == null || !answers[0].equals(mGenerated[mQuizPositions[0]])
                    || !answers[1].equals(mGenerated[mQuizPositions[1]])) {
                mQuizSecond.setError(getString(R.string.cifra_quiz_failed));
                return;
            }
            words = mGenerated.clone();
        } else {
            final String[] typed = Bip39.split(mWords.getText());
            words = mWordlist.canonicalize(typed);
            try {
                if (words == null) {
                    throw new Bip39.InvalidMnemonicException(
                            Bip39.InvalidMnemonicException.Reason.UNKNOWN_WORD, 0);
                }
                mWordlist.validate(words);
            } catch (Bip39.InvalidMnemonicException e) {
                updateWordsStatus();
                mWords.requestFocus();
                return;
            }
        }

        final String passphrase = mPassphrase.getText().toString();
        final VaultStore store = VaultStore.getInstance(this);
        if (!store.isDeviceSecure()) {
            Toast.makeText(this, R.string.cifra_no_lock_screen, Toast.LENGTH_LONG).show();
            return;
        }
        // Wrapping the new secret key needs the Keystore key that only works right after the
        // owner authenticated.
        DeviceAuth.request(this, getString(R.string.cifra_auth_title_create), authenticated -> {
            if (isFinishing() || isDestroyed()) {
                Arrays.fill(words, null);
                return;
            }
            if (!authenticated) {
                Arrays.fill(words, null);
                Toast.makeText(this, R.string.cifra_auth_failed, Toast.LENGTH_LONG).show();
                return;
            }
            setBusy(true);
            VaultStore.runAsync(() -> store.createIdentity(name, words, passphrase),
                    (identity, error) -> {
                        Arrays.fill(words, null);
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        setBusy(false);
                        if (error != null) {
                            Toast.makeText(this, errorMessage(error), Toast.LENGTH_LONG).show();
                            return;
                        }
                        Toast.makeText(this, R.string.cifra_identity_created,
                                Toast.LENGTH_SHORT).show();
                        finish();
                    });
        });
    }

    private static int errorMessage(final VaultStore.VaultException error) {
        switch (error.mReason) {
            case DUPLICATE:
                return R.string.cifra_duplicate_identity;
            case DEVICE_LOCKED:
                return R.string.cifra_error_locked;
            case AUTH_REQUIRED:
                return R.string.cifra_error_auth_expired;
            case NO_LOCK_SCREEN:
                return R.string.cifra_no_lock_screen;
            default:
                return R.string.cifra_error_generic;
        }
    }

    private void setBusy(final boolean busy) {
        mProgress.setVisibility(busy ? View.VISIBLE : View.GONE);
        mSave.setEnabled(!busy);
        mSave.setText(busy ? R.string.cifra_deriving : R.string.cifra_save_identity);
    }

    private void wipeGenerated() {
        if (mGenerated != null) {
            Arrays.fill(mGenerated, null);
            mGenerated = null;
        }
        mGeneratedWords.setText(null);
    }

    private void wipe() {
        wipeGenerated();
        for (final EditText field : new EditText[] { mWords, mQuizFirst, mQuizSecond,
                mPassphrase, mPassphraseConfirm }) {
            if (field != null) {
                field.getText().clear();
            }
        }
    }

    /** Splits the words on spaces for auto-completion. */
    private static final class SpaceTokenizer implements MultiAutoCompleteTextView.Tokenizer {
        @Override
        public int findTokenStart(final CharSequence text, final int cursor) {
            int i = cursor;
            while (i > 0 && !Character.isWhitespace(text.charAt(i - 1))) {
                i--;
            }
            return i;
        }

        @Override
        public int findTokenEnd(final CharSequence text, final int cursor) {
            int i = cursor;
            while (i < text.length() && !Character.isWhitespace(text.charAt(i))) {
                i++;
            }
            return i;
        }

        @Override
        public CharSequence terminateToken(final CharSequence text) {
            return text + " ";
        }
    }

    /** Disables the copy/cut/share text selection menu. */
    private static final class NoCopyActionMode implements ActionMode.Callback {
        @Override
        public boolean onCreateActionMode(final ActionMode mode, final Menu menu) {
            return false;
        }

        @Override
        public boolean onPrepareActionMode(final ActionMode mode, final Menu menu) {
            return false;
        }

        @Override
        public boolean onActionItemClicked(final ActionMode mode, final MenuItem item) {
            return false;
        }

        @Override
        public void onDestroyActionMode(final ActionMode mode) {
        }
    }
}
