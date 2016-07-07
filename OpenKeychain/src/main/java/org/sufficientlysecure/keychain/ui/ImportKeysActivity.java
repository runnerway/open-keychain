/*
 * Copyright (C) 2012-2014 Dominik Schürmann <dominik@dominikschuermann.de>
 * Copyright (C) 2011 Senecaso
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

package org.sufficientlysecure.keychain.ui;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.View;
import android.view.ViewGroup;

import org.sufficientlysecure.keychain.Constants;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.intents.OpenKeychainIntents;
import org.sufficientlysecure.keychain.keyimport.FacebookKeyserver;
import org.sufficientlysecure.keychain.keyimport.ImportKeysListEntry;
import org.sufficientlysecure.keychain.keyimport.ParcelableKeyRing;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.service.ImportKeyringParcel;
import org.sufficientlysecure.keychain.ui.base.BaseActivity;
import org.sufficientlysecure.keychain.ui.base.CryptoOperationHelper;
import org.sufficientlysecure.keychain.ui.loader.BytesLoaderState;
import org.sufficientlysecure.keychain.ui.loader.CloudLoaderState;
import org.sufficientlysecure.keychain.ui.loader.LoaderState;
import org.sufficientlysecure.keychain.ui.util.KeyFormattingUtils;
import org.sufficientlysecure.keychain.ui.util.Notify;
import org.sufficientlysecure.keychain.util.Log;
import org.sufficientlysecure.keychain.util.ParcelableFileCache;
import org.sufficientlysecure.keychain.util.ParcelableFileCache.IteratorWithSize;
import org.sufficientlysecure.keychain.util.Preferences;

import java.io.IOException;
import java.util.ArrayList;

public class ImportKeysActivity extends BaseActivity
        implements CryptoOperationHelper.Callback<ImportKeyringParcel, ImportKeyResult> {

    public static final String ACTION_IMPORT_KEY = OpenKeychainIntents.IMPORT_KEY;
    public static final String ACTION_IMPORT_KEY_FROM_KEYSERVER = OpenKeychainIntents.IMPORT_KEY_FROM_KEYSERVER;
    public static final String ACTION_IMPORT_KEY_FROM_FACEBOOK
            = Constants.INTENT_PREFIX + "IMPORT_KEY_FROM_FACEBOOK";
    public static final String ACTION_IMPORT_KEY_FROM_KEYSERVER_AND_RETURN_RESULT =
            Constants.INTENT_PREFIX + "IMPORT_KEY_FROM_KEY_SERVER_AND_RETURN_RESULT";
    public static final String ACTION_IMPORT_KEY_FROM_FILE_AND_RETURN = Constants.INTENT_PREFIX
            + "IMPORT_KEY_FROM_FILE_AND_RETURN";

    // Actions for internal use only:
    public static final String ACTION_IMPORT_KEY_FROM_FILE = Constants.INTENT_PREFIX
            + "IMPORT_KEY_FROM_FILE";
    public static final String ACTION_SEARCH_KEYSERVER_FROM_URL = Constants.INTENT_PREFIX
            + "SEARCH_KEYSERVER_FROM_URL";
    public static final String EXTRA_RESULT = "result";

    // only used by ACTION_IMPORT_KEY
    public static final String EXTRA_KEY_BYTES = OpenKeychainIntents.IMPORT_EXTRA_KEY_EXTRA_KEY_BYTES;

    // only used by ACTION_IMPORT_KEY_FROM_KEYSERVER
    public static final String EXTRA_QUERY = OpenKeychainIntents.IMPORT_KEY_FROM_KEYSERVER_EXTRA_QUERY;
    public static final String EXTRA_KEY_ID = Constants.EXTRA_PREFIX + "EXTRA_KEY_ID";
    public static final String EXTRA_FINGERPRINT = OpenKeychainIntents.IMPORT_KEY_FROM_KEYSERVER_EXTRA_FINGERPRINT;

    public static final String TAG_FRAG_LIST = "frag_list";
    public static final String TAG_FRAG_TOP = "frag_top";

    // for CryptoOperationHelper.Callback
    private String mKeyserver;
    private ArrayList<ParcelableKeyRing> mKeyList;

    private CryptoOperationHelper<ImportKeyringParcel, ImportKeyResult> mOperationHelper;

    private boolean mFreshIntent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // we're started with a new Intent that needs to be handled by onResumeFragments
        mFreshIntent = true;

        setFullScreenDialogClose(Activity.RESULT_CANCELED, true);
    }

    @Override
    protected void initLayout() {
        setContentView(R.layout.import_keys_activity);
    }

    @Override
    protected void onResumeFragments() {
        super.onResumeFragments();
        if (mFreshIntent) {
            handleActions(getIntent());
            // we've consumed this Intent, we don't want to repeat the action it represents
            // every time the activity is resumed
            mFreshIntent = false;
        }
    }

    @Override
    protected void onRestoreInstanceState(Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);

        // the only thing we need to take care of for restoring state is
        // that the top layout is shown iff it contains a fragment
        Fragment topFragment = getSupportFragmentManager().findFragmentByTag(TAG_FRAG_TOP);
        boolean hasTopFragment = topFragment != null;
        findViewById(R.id.import_keys_top_layout).setVisibility(hasTopFragment ? View.VISIBLE : View.GONE);
    }

    protected void handleActions(@NonNull Intent intent) {
        String action = intent.getAction();
        Bundle extras = intent.getExtras();
        Uri dataUri = intent.getData();
        String scheme = intent.getScheme();

        if (extras == null) {
            extras = new Bundle();
        }

        if (Intent.ACTION_VIEW.equals(action)) {
            if (FacebookKeyserver.isFacebookHost(dataUri)) {
                action = ACTION_IMPORT_KEY_FROM_FACEBOOK;
            } else if ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) {
                action = ACTION_SEARCH_KEYSERVER_FROM_URL;
            } else if ("openpgp4fpr".equalsIgnoreCase(scheme)) {
                action = ACTION_IMPORT_KEY_FROM_KEYSERVER;
                extras.putString(EXTRA_FINGERPRINT, dataUri.getSchemeSpecificPart());
            } else {
                // Android's Action when opening file associated to Keychain (see AndroidManifest.xml)
                // delegate action to ACTION_IMPORT_KEY
                action = ACTION_IMPORT_KEY;
            }
        }
        if (action == null) {
            // -> switch to default below
            action = "";
        }

        switch (action) {
            case ACTION_IMPORT_KEY: {
                if (dataUri != null) {
                    // action: directly load data
                    startListFragment(null, dataUri, null, null);
                } else if (extras.containsKey(EXTRA_KEY_BYTES)) {
                    byte[] importData = extras.getByteArray(EXTRA_KEY_BYTES);

                    // action: directly load data
                    startListFragment(importData, null, null, null);
                } else {
                    startTopFileFragment();
                    startListFragment(null, null, null, null);
                }
                break;
            }
            case ACTION_IMPORT_KEY_FROM_KEYSERVER:
            case ACTION_IMPORT_KEY_FROM_KEYSERVER_AND_RETURN_RESULT: {

                if (extras.containsKey(EXTRA_QUERY) || extras.containsKey(EXTRA_KEY_ID)) {
                    /* simple search based on query or key id */

                    String query = null;
                    if (extras.containsKey(EXTRA_QUERY)) {
                        query = extras.getString(EXTRA_QUERY);
                    } else if (extras.containsKey(EXTRA_KEY_ID)) {
                        long keyId = extras.getLong(EXTRA_KEY_ID, 0);
                        if (keyId != 0) {
                            query = KeyFormattingUtils.convertKeyIdToHex(keyId);
                        }
                    }

                    if (query != null && query.length() > 0) {
                        // display keyserver fragment with query
                        startTopCloudFragment(query, false, null);

                        // action: search immediately
                        startListFragment(null, null, query, null);
                    } else {
                        Log.e(Constants.TAG, "Query is empty!");
                        return;
                    }
                } else if (extras.containsKey(EXTRA_FINGERPRINT)) {
                    /*
                     * search based on fingerprint, here we can enforce a check in the end
                     * if the right key has been downloaded
                     */

                    String fingerprint = extras.getString(EXTRA_FINGERPRINT);
                    if (isFingerprintValid(fingerprint)) {
                        String query = "0x" + fingerprint;

                        // display keyserver fragment with query
                        startTopCloudFragment(query, true, null);

                        // action: search immediately
                        startListFragment(null, null, query, null);
                    }
                } else {
                    Log.e(Constants.TAG,
                            "IMPORT_KEY_FROM_KEYSERVER action needs to contain the 'query', 'key_id', or " +
                                    "'fingerprint' extra!"
                    );
                    return;
                }
                break;
            }
            case ACTION_IMPORT_KEY_FROM_FACEBOOK: {
                String fbUsername = FacebookKeyserver.getUsernameFromUri(dataUri);

                Preferences.CloudSearchPrefs cloudSearchPrefs =
                        new Preferences.CloudSearchPrefs(false, true, true, null);
                // we allow our users to edit the query if they wish
                startTopCloudFragment(fbUsername, false, cloudSearchPrefs);
                // search immediately
                startListFragment(null, null, fbUsername, cloudSearchPrefs);
                break;
            }
            case ACTION_SEARCH_KEYSERVER_FROM_URL: {
                // need to process URL to get search query and keyserver authority
                String query = dataUri.getQueryParameter("search");
                // if query not specified, we still allow users to search the keyserver in the link
                if (query == null) {
                    Notify.create(this, R.string.import_url_warn_no_search_parameter, Notify.LENGTH_INDEFINITE,
                            Notify.Style.WARN).show();
                }
                Preferences.CloudSearchPrefs cloudSearchPrefs = new Preferences.CloudSearchPrefs(
                        true, true, true, dataUri.getAuthority());
                // we allow our users to edit the query if they wish
                startTopCloudFragment(query, false, cloudSearchPrefs);
                // search immediately (if query is not null)
                startListFragment(null, null, query, cloudSearchPrefs);
                break;
            }
            case ACTION_IMPORT_KEY_FROM_FILE:
            case ACTION_IMPORT_KEY_FROM_FILE_AND_RETURN: {
                // NOTE: this only displays the appropriate fragment, no actions are taken
                startTopFileFragment();
                startListFragment(null, null, null, null);
                break;
            }
            default: {
                startTopCloudFragment(null, false, null);
                startListFragment(null, null, null, null);
                break;
            }
        }
    }

    /**
     * Shows the list of keys to be imported.
     * If the fragment is started with non-null bytes/dataUri/serverQuery, it will immediately
     * load content.
     *
     * @param bytes            bytes containing list of keyrings to import
     * @param dataUri          uri to file to import keyrings from
     * @param serverQuery      query to search for on the keyserver
     * @param cloudSearchPrefs search specifications to use. If null will retrieve from user's
     *                         preferences.
     */
    private void startListFragment(byte[] bytes, Uri dataUri, String serverQuery,
                                   Preferences.CloudSearchPrefs cloudSearchPrefs) {
        Fragment listFragment =
                ImportKeysListFragment.newInstance(bytes, dataUri, serverQuery, false,
                        cloudSearchPrefs);
        getSupportFragmentManager().beginTransaction()
                .replace(R.id.import_keys_list_container, listFragment, TAG_FRAG_LIST)
                .commit();
    }

    private void startTopFileFragment() {
        findViewById(R.id.import_keys_top_layout).setVisibility(View.VISIBLE);
        Fragment importFileFragment = ImportKeysFileFragment.newInstance();
        getSupportFragmentManager().beginTransaction()
                .replace(R.id.import_keys_top_container, importFileFragment, TAG_FRAG_TOP)
                .commit();
    }

    /**
     * loads the CloudFragment, which consists of the search bar, search button and settings icon
     * visually.
     *
     * @param query            search query
     * @param disableQueryEdit if true, user will not be able to edit the search query
     * @param cloudSearchPrefs keyserver authority to use for search, if null will use keyserver
     *                         specified in user preferences
     */
    private void startTopCloudFragment(String query, boolean disableQueryEdit,
                                       Preferences.CloudSearchPrefs cloudSearchPrefs) {
        findViewById(R.id.import_keys_top_layout).setVisibility(View.VISIBLE);
        Fragment importCloudFragment = ImportKeysCloudFragment.newInstance(query, disableQueryEdit,
                cloudSearchPrefs);
        getSupportFragmentManager().beginTransaction()
                .replace(R.id.import_keys_top_container, importCloudFragment, TAG_FRAG_TOP)
                .commit();
    }

    private boolean isFingerprintValid(String fingerprint) {
        if (fingerprint == null || fingerprint.length() < 40) {
            Notify.create(this, R.string.import_qr_code_too_short_fingerprint, Notify.Style.ERROR)
                    .show((ViewGroup) findViewById(R.id.import_snackbar));
            return false;
        } else {
            return true;
        }
    }

    public void loadCallback(LoaderState loaderState) {
        FragmentManager fragMan = getSupportFragmentManager();
        ImportKeysListFragment keyListFragment = (ImportKeysListFragment) fragMan.findFragmentByTag(TAG_FRAG_LIST);
        keyListFragment.loadNew(loaderState);
    }

    private void importSelectedKeys() {

        FragmentManager fragMan = getSupportFragmentManager();
        ImportKeysListFragment keyListFragment = (ImportKeysListFragment) fragMan.findFragmentByTag(TAG_FRAG_LIST);

        if (keyListFragment.getSelectedEntries().size() == 0) {
            Notify.create(this, R.string.error_nothing_import_selected, Notify.Style.ERROR)
                    .show((ViewGroup) findViewById(R.id.import_snackbar));
            return;
        }

        mOperationHelper = new CryptoOperationHelper<>(
                1, this, this, R.string.progress_importing
        );

        LoaderState ls = keyListFragment.getLoaderState();
        if (ls instanceof BytesLoaderState) {
            Log.d(Constants.TAG, "importKeys started");

            // get DATA from selected key entries
            IteratorWithSize<ParcelableKeyRing> selectedEntries = keyListFragment.getSelectedData();

            // instead of giving the entries by Intent extra, cache them into a
            // file to prevent Java Binder problems on heavy imports
            // read FileImportCache for more info.
            try {
                // We parcel this iteratively into a file - anything we can
                // display here, we should be able to import.
                ParcelableFileCache<ParcelableKeyRing> cache =
                        new ParcelableFileCache<>(this, "key_import.pcl");
                cache.writeCache(selectedEntries);

                mKeyList = null;
                mKeyserver = null;
                mOperationHelper.cryptoOperation();

            } catch (IOException e) {
                Log.e(Constants.TAG, "Problem writing cache file", e);
                Notify.create(this, "Problem writing cache file!", Notify.Style.ERROR)
                        .show((ViewGroup) findViewById(R.id.import_snackbar));
            }
        } else if (ls instanceof CloudLoaderState) {
            CloudLoaderState sls = (CloudLoaderState) ls;

            // get selected key entries
            ArrayList<ParcelableKeyRing> keys = new ArrayList<>();
            {
                // change the format into ParcelableKeyRing
                ArrayList<ImportKeysListEntry> entries = keyListFragment.getSelectedEntries();
                for (ImportKeysListEntry entry : entries) {
                    keys.add(new ParcelableKeyRing(entry.getFingerprintHex(),
                            entry.getKeyIdHex(), entry.getKeybaseName(), entry.getFbUsername()));
                }
            }

            mKeyList = keys;
            mKeyserver = sls.mCloudPrefs.keyserver;
            mOperationHelper.cryptoOperation();

        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (mOperationHelper != null &&
                mOperationHelper.handleActivityResult(requestCode, resultCode, data)) {
            return;
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    /**
     * Defines how the result of this activity is returned.
     * Is overwritten in RemoteImportKeysActivity
     */
    protected void handleResult(ImportKeyResult result) {
        String intentAction = getIntent().getAction();

        if (ACTION_IMPORT_KEY_FROM_KEYSERVER_AND_RETURN_RESULT.equals(intentAction)
                || ACTION_IMPORT_KEY_FROM_FILE_AND_RETURN.equals(intentAction)) {
            Intent intent = new Intent();
            intent.putExtra(ImportKeyResult.EXTRA_RESULT, result);
            setResult(RESULT_OK, intent);
            finish();
        } else if (result.isOkNew() || result.isOkUpdated()) {
            // User has successfully imported a key, hide first time dialog
            Preferences.getPreferences(this).setFirstTime(false);

            // Close activities opened for importing keys and go to the list of keys
            Intent intent = new Intent(this, MainActivity.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
        } else {
            result.createNotify(ImportKeysActivity.this)
                    .show((ViewGroup) findViewById(R.id.import_snackbar));
        }
    }

    // methods from CryptoOperationHelper.Callback

    @Override
    public ImportKeyringParcel createOperationInput() {
        return new ImportKeyringParcel(mKeyList, mKeyserver);
    }

    @Override
    public void onCryptoOperationSuccess(ImportKeyResult result) {
        handleResult(result);
    }

    @Override
    public void onCryptoOperationCancelled() {
        // do nothing
    }

    @Override
    public void onCryptoOperationError(ImportKeyResult result) {
        handleResult(result);
    }

    @Override
    public boolean onCryptoSetProgress(String msg, int progress, int max) {
        return false;
    }
}
