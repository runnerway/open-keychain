/*
 * Copyright (C) 2013-2014 Dominik Schürmann <dominik@dominikschuermann.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.sufficientlysecure.keychain.ui.adapter;

import android.content.Context;
import android.content.res.Resources;
import android.databinding.DataBindingUtil;
import android.graphics.Color;
import android.support.v4.app.Fragment;
import android.support.v7.widget.RecyclerView;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import org.openintents.openpgp.util.OpenPgpUtils;
import org.sufficientlysecure.keychain.Constants;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.databinding.ImportKeysListItemBinding;
import org.sufficientlysecure.keychain.keyimport.ImportKeysListEntry;
import org.sufficientlysecure.keychain.keyimport.ParcelableKeyRing;
import org.sufficientlysecure.keychain.keyimport.processing.BytesLoaderState;
import org.sufficientlysecure.keychain.keyimport.processing.CloudLoaderState;
import org.sufficientlysecure.keychain.keyimport.processing.ImportKeysListener;
import org.sufficientlysecure.keychain.keyimport.processing.LoaderState;
import org.sufficientlysecure.keychain.operations.ImportOperation;
import org.sufficientlysecure.keychain.operations.results.ImportKeyResult;
import org.sufficientlysecure.keychain.pgp.CanonicalizedKeyRing;
import org.sufficientlysecure.keychain.pgp.CanonicalizedPublicKeyRing;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKeyRing;
import org.sufficientlysecure.keychain.pgp.KeyRing;
import org.sufficientlysecure.keychain.service.ImportKeyringParcel;
import org.sufficientlysecure.keychain.ui.base.CryptoOperationHelper;
import org.sufficientlysecure.keychain.ui.util.FormattingUtils;
import org.sufficientlysecure.keychain.ui.util.Highlighter;
import org.sufficientlysecure.keychain.ui.util.KeyFormattingUtils;
import org.sufficientlysecure.keychain.ui.util.KeyFormattingUtils.State;
import org.sufficientlysecure.keychain.util.Log;
import org.sufficientlysecure.keychain.util.ParcelableFileCache;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

public class ImportKeysAdapter extends RecyclerView.Adapter<ImportKeysAdapter.ViewHolder> implements
        CryptoOperationHelper.Callback<ImportKeyringParcel, ImportKeyResult> {

    private Context mContext;
    private Fragment mFragment;
    private ImportKeysListener mListener;
    private boolean mNonInteractive;

    private LoaderState mLoaderState;
    private List<ImportKeysListEntry> mData;

    private String mKeyserver = null;
    private ArrayList<ParcelableKeyRing> mKeyList = null;

    public ImportKeysAdapter(Context context, Fragment fragment, ImportKeysListener listener, boolean mNonInteractive) {
        this.mContext = context;
        this.mFragment = fragment;
        this.mListener = listener;
        this.mNonInteractive = mNonInteractive;
    }

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public ImportKeysListItemBinding binding;

        public ViewHolder(View view) {
            super(view);
            binding = DataBindingUtil.bind(view);
        }
    }

    public void clearData() {
        mData = null;
        notifyDataSetChanged();
    }

    public void setLoaderState(LoaderState loaderState) {
        this.mLoaderState = loaderState;
    }

    public void setData(List<ImportKeysListEntry> data) {
        this.mData = data;
        notifyDataSetChanged();
    }

    /**
     * This method returns a list of all selected entries, with public keys sorted
     * before secret keys, see ImportOperation for specifics.
     *
     * @see ImportOperation
     */
    public List<ImportKeysListEntry> getEntries() {
        ArrayList<ImportKeysListEntry> result = new ArrayList<>();
        ArrayList<ImportKeysListEntry> secrets = new ArrayList<>();
        if (mData == null) {
            return result;
        }
        for (ImportKeysListEntry entry : mData) {
            // add this entry to either the secret or the public list
            (entry.isSecretKey() ? secrets : result).add(entry);
        }
        // add secret keys at the end of the list
        result.addAll(secrets);
        return result;
    }

    @Override
    public ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        LayoutInflater inflater = LayoutInflater.from(mContext);
        View v = inflater.inflate(R.layout.import_keys_list_item, parent, false);
        ViewHolder vh = new ViewHolder(v);
        return vh;
    }

    @Override
    public void onBindViewHolder(final ViewHolder holder, int position) {
        final ImportKeysListItemBinding b = holder.binding;
        final ImportKeysListEntry entry = mData.get(position);

        Resources resources = mContext.getResources();
        Highlighter highlighter = new Highlighter(mContext, entry.getQuery());
        b.setStandardColor(FormattingUtils.getColorFromAttr(mContext, R.attr.colorText));
        b.setRevokedExpiredColor(resources.getColor(R.color.key_flag_gray));
        b.setSecretColor(Color.RED);
        b.setHighlighter(highlighter);

        b.setSecret(entry.isSecretKey());
        b.setExpired(entry.isExpired());
        b.setRevoked(entry.isRevoked());

        String userId = entry.getUserIds().get(0); // main user id
        OpenPgpUtils.UserId userIdSplit = KeyRing.splitUserId(userId);

        b.setAlgorithm(entry.getAlgorithm());
        b.setUserId(userIdSplit.name);
        b.setUserIdEmail(userIdSplit.email);
        b.setKeyId(KeyFormattingUtils.beautifyKeyIdWithPrefix(mContext, entry.getKeyIdHex()));

        if (entry.isRevoked()) {
            KeyFormattingUtils.setStatusImage(mContext, b.status, null, State.REVOKED, R.color.key_flag_gray);
        } else if (entry.isExpired()) {
            KeyFormattingUtils.setStatusImage(mContext, b.status, null, State.EXPIRED, R.color.key_flag_gray);
        }

        b.importKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (mLoaderState instanceof BytesLoaderState) {
                    mListener.importKey(new ParcelableKeyRing(entry.getEncodedRing()));
                } else if (mLoaderState instanceof CloudLoaderState) {
                    mListener.importKey(new ParcelableKeyRing(entry.getFingerprintHex(), entry.getKeyIdHex(),
                            entry.getKeybaseName(), entry.getFbUsername()));
                }
            }
        });

        b.expand.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                boolean hidden = b.extraContainer.getVisibility() == View.GONE;
                b.extraContainer.setVisibility(hidden ? View.VISIBLE : View.GONE);
                b.expand.animate().rotation(hidden ? 180 : 0).start();

                if (hidden) {
                    if (mLoaderState instanceof BytesLoaderState) {
                        getKey(new ParcelableKeyRing(entry.getEncodedRing()));
                    } else if (mLoaderState instanceof CloudLoaderState) {
                        getKey(new ParcelableKeyRing(entry.getFingerprintHex(), entry.getKeyIdHex(),
                                entry.getKeybaseName(), entry.getFbUsername()));
                    }
                }
            }
        });

        if (entry.getUserIds().size() == 1) {
            b.userIdsList.setVisibility(View.GONE);
        } else {
            b.userIdsList.setVisibility(View.VISIBLE);

            // destroyLoader view from holder
            b.userIdsList.removeAllViews();

            // we want conventional gpg UserIDs first, then Keybase ”proofs”
            HashMap<String, HashSet<String>> mergedUserIds = entry.getMergedUserIds();
            ArrayList<Map.Entry<String, HashSet<String>>> sortedIds = new ArrayList<Map.Entry<String, HashSet<String>>>(mergedUserIds.entrySet());
            Collections.sort(sortedIds, new java.util.Comparator<Map.Entry<String, HashSet<String>>>() {
                @Override
                public int compare(Map.Entry<String, HashSet<String>> entry1, Map.Entry<String, HashSet<String>> entry2) {

                    // sort keybase UserIds after non-Keybase
                    boolean e1IsKeybase = entry1.getKey().contains(":");
                    boolean e2IsKeybase = entry2.getKey().contains(":");
                    if (e1IsKeybase != e2IsKeybase) {
                        return (e1IsKeybase) ? 1 : -1;
                    }
                    return entry1.getKey().compareTo(entry2.getKey());
                }
            });

            for (Map.Entry<String, HashSet<String>> pair : sortedIds) {
                String cUserId = pair.getKey();
                HashSet<String> cEmails = pair.getValue();

                LayoutInflater inflater = LayoutInflater.from(mContext);

                TextView uidView = (TextView) inflater.inflate(
                        R.layout.import_keys_list_entry_user_id, null);
                uidView.setText(highlighter.highlight(cUserId));
                uidView.setPadding(0, 0, FormattingUtils.dpToPx(mContext, 8), 0);

                if (entry.isRevoked() || entry.isExpired()) {
                    uidView.setTextColor(mContext.getResources().getColor(R.color.key_flag_gray));
                } else {
                    uidView.setTextColor(FormattingUtils.getColorFromAttr(mContext, R.attr.colorText));
                }

                b.userIdsList.addView(uidView);

                for (String email : cEmails) {
                    TextView emailView = (TextView) inflater.inflate(
                            R.layout.import_keys_list_entry_user_id, null);
                    emailView.setPadding(
                            FormattingUtils.dpToPx(mContext, 16), 0,
                            FormattingUtils.dpToPx(mContext, 8), 0);
                    emailView.setText(highlighter.highlight(email));

                    if (entry.isRevoked() || entry.isExpired()) {
                        emailView.setTextColor(mContext.getResources().getColor(R.color.key_flag_gray));
                    } else {
                        emailView.setTextColor(FormattingUtils.getColorFromAttr(mContext, R.attr.colorText));
                    }

                    b.userIdsList.addView(emailView);
                }
            }
        }
    }

    @Override
    public int getItemCount() {
        return mData != null ? mData.size() : 0;
    }

    public void getKey(ParcelableKeyRing keyRing) {
        Log.d(Constants.TAG, "getKey started");
        if (mLoaderState instanceof BytesLoaderState) {
            // instead of giving the entries by Intent extra, cache them into a
            // file to prevent Java Binder problems on heavy imports
            // read FileImportCache for more info.
            try {
                // We parcel this iteratively into a file - anything we can
                // display here, we should be able to import.
                ParcelableFileCache<ParcelableKeyRing> cache =
                        new ParcelableFileCache<>(mContext, ImportOperation.CACHE_FILE_NAME);
                cache.writeCache(keyRing);
            } catch (IOException e) {
                Log.e(Constants.TAG, "Problem writing cache file", e);
                //TODO Notify.create(mContext, "Problem writing cache file!", Notify.Style.ERROR).show();
                return;
            }
        } else if (mLoaderState instanceof CloudLoaderState) {
            ArrayList<ParcelableKeyRing> keys = new ArrayList<>();
            keys.add(keyRing);

            mKeyList = keys;
            mKeyserver = ((CloudLoaderState) mLoaderState).mCloudPrefs.keyserver;
        }

        CryptoOperationHelper<ImportKeyringParcel, ImportKeyResult> operationHelper;
        operationHelper = new CryptoOperationHelper(1, mFragment, this, R.string.progress_importing);
        operationHelper.cryptoOperation();
    }

    @Override
    public ImportKeyringParcel createOperationInput() {
        return new ImportKeyringParcel(mKeyList, mKeyserver, true);
    }

    @Override
    public void onCryptoOperationSuccess(ImportKeyResult result) {
        ArrayList<CanonicalizedPublicKeyRing> canPublicKeyRings = result.mCanonicalizedPublicKeyRings;
        ArrayList<CanonicalizedSecretKeyRing> canSecretKeyRings = result.mCanonicalizedSecretKeyRings;
        Log.d("onCryptoOperationSuccess", "SizeSecret: " + canSecretKeyRings.size() + "\n"
                + "SizePublic: " + canPublicKeyRings.size());
    }

    @Override
    public void onCryptoOperationCancelled() {

    }

    @Override
    public void onCryptoOperationError(ImportKeyResult result) {

    }

    @Override
    public boolean onCryptoSetProgress(String msg, int progress, int max) {
        return false;
    }

}
