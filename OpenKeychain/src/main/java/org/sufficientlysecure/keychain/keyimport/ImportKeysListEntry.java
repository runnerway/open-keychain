/*
 * Copyright (C) 2013 Dominik Schürmann <dominik@dominikschuermann.de>
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

package org.sufficientlysecure.keychain.keyimport;

import android.content.Context;
import android.os.Parcel;
import android.os.Parcelable;

import org.openintents.openpgp.util.OpenPgpUtils;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.pgp.KeyRing;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.pgp.UncachedPublicKey;
import org.sufficientlysecure.keychain.ui.util.KeyFormattingUtils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;

public class ImportKeysListEntry implements Serializable, Parcelable {
    private static final long serialVersionUID = -7797972103284992662L;

    private ArrayList<String> mUserIds;
    private HashMap<String, HashSet<String>> mMergedUserIds;
    private long mKeyId;
    private String mKeyIdHex;
    private boolean mRevoked;
    private boolean mExpired;
    private Date mDate; // TODO: not displayed
    private String mFingerprintHex;
    private Integer mBitStrength;
    private String mCurveOid;
    private String mAlgorithm;
    private boolean mSecretKey;
    private String mPrimaryUserId;
    private String mKeybaseName;
    private String mFbUsername;
    private String mQuery;
    private ArrayList<String> mOrigins;
    private Integer mHashCode = null;

    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(mPrimaryUserId);
        dest.writeStringList(mUserIds);
        dest.writeSerializable(mMergedUserIds);
        dest.writeLong(mKeyId);
        dest.writeByte((byte) (mRevoked ? 1 : 0));
        dest.writeByte((byte) (mExpired ? 1 : 0));
        dest.writeInt(mDate == null ? 0 : 1);
        if (mDate != null) {
            dest.writeLong(mDate.getTime());
        }
        dest.writeString(mFingerprintHex);
        dest.writeString(mKeyIdHex);
        dest.writeInt(mBitStrength == null ? 0 : 1);
        if (mBitStrength != null) {
            dest.writeInt(mBitStrength);
        }
        dest.writeString(mAlgorithm);
        dest.writeByte((byte) (mSecretKey ? 1 : 0));
        dest.writeString(mKeybaseName);
        dest.writeString(mFbUsername);
        dest.writeStringList(mOrigins);
    }

    public static final Creator<ImportKeysListEntry> CREATOR = new Creator<ImportKeysListEntry>() {
        public ImportKeysListEntry createFromParcel(final Parcel source) {
            ImportKeysListEntry vr = new ImportKeysListEntry();
            vr.mPrimaryUserId = source.readString();
            vr.mUserIds = new ArrayList<>();
            source.readStringList(vr.mUserIds);
            vr.mMergedUserIds = (HashMap<String, HashSet<String>>) source.readSerializable();
            vr.mKeyId = source.readLong();
            vr.mRevoked = source.readByte() == 1;
            vr.mExpired = source.readByte() == 1;
            vr.mDate = source.readInt() != 0 ? new Date(source.readLong()) : null;
            vr.mFingerprintHex = source.readString();
            vr.mKeyIdHex = source.readString();
            vr.mBitStrength = source.readInt() != 0 ? source.readInt() : null;
            vr.mAlgorithm = source.readString();
            vr.mSecretKey = source.readByte() == 1;
            vr.mKeybaseName = source.readString();
            vr.mFbUsername = source.readString();
            vr.mOrigins = new ArrayList<>();
            source.readStringList(vr.mOrigins);

            return vr;
        }

        public ImportKeysListEntry[] newArray(final int size) {
            return new ImportKeysListEntry[size];
        }
    };

    public int hashCode() {
        if (mHashCode != null) {
            return mHashCode;
        }
        return super.hashCode();
    }

    public boolean hasSameKeyAs(ImportKeysListEntry other) {
        if (mFingerprintHex == null || other == null) {
            return false;
        }
        return mFingerprintHex.equals(other.mFingerprintHex);
    }

    public String getKeyIdHex() {
        return mKeyIdHex;
    }

    public boolean isExpired() {
        return mExpired;
    }

    public void setExpired(boolean expired) {
        mExpired = expired;
    }

    public long getKeyId() {
        return mKeyId;
    }

    public void setKeyId(long keyId) {
        mKeyId = keyId;
    }

    public void setKeyIdHex(String keyIdHex) {
        mKeyIdHex = keyIdHex;
    }

    public boolean isRevoked() {
        return mRevoked;
    }

    public void setRevoked(boolean revoked) {
        mRevoked = revoked;
    }

    public Date getDate() {
        return mDate;
    }

    public void setDate(Date date) {
        mDate = date;
    }

    public String getFingerprintHex() {
        return mFingerprintHex;
    }

    public void setFingerprintHex(String fingerprintHex) {
        mFingerprintHex = fingerprintHex;
    }

    public Integer getBitStrength() {
        return mBitStrength;
    }

    public String getCurveOid() {
        return mCurveOid;
    }

    public void setBitStrength(int bitStrength) {
        mBitStrength = bitStrength;
    }

    public String getAlgorithm() {
        return mAlgorithm;
    }

    public void setAlgorithm(String algorithm) {
        mAlgorithm = algorithm;
    }

    public boolean isSecretKey() {
        return mSecretKey;
    }

    public void setSecretKey(boolean secretKey) {
        mSecretKey = secretKey;
    }

    public ArrayList<String> getUserIds() {
        return mUserIds;
    }

    public void setUserIds(ArrayList<String> userIds) {
        mUserIds = userIds;
        updateMergedUserIds();
    }

    public String getPrimaryUserId() {
        return mPrimaryUserId;
    }

    public void setPrimaryUserId(String uid) {
        mPrimaryUserId = uid;
    }

    public String getKeybaseName() {
        return mKeybaseName;
    }

    public String getFbUsername() {
        return mFbUsername;
    }

    public void setKeybaseName(String keybaseName) {
        mKeybaseName = keybaseName;
    }

    public void setFbUsername(String fbUsername) {
        mFbUsername = fbUsername;
    }

    public String getQuery() {
        return mQuery;
    }

    public void setQuery(String query) {
        mQuery = query;
    }

    public ArrayList<String> getOrigins() {
        return mOrigins;
    }

    public void addOrigin(String origin) {
        mOrigins.add(origin);
    }

    public HashMap<String, HashSet<String>> getMergedUserIds() {
        return mMergedUserIds;
    }

    /**
     * Constructor for later querying from keyserver
     */
    public ImportKeysListEntry() {
        // keys from keyserver are always public keys; from keybase too
        mSecretKey = false;

        mUserIds = new ArrayList<>();
        mOrigins = new ArrayList<>();
    }

    /**
     * Constructor based on key object, used for import from NFC, QR Codes, files
     */
    @SuppressWarnings("unchecked")
    public ImportKeysListEntry(Context context, UncachedKeyRing ring) {
        mSecretKey = ring.isSecret();
        UncachedPublicKey key = ring.getPublicKey();

        mHashCode = key.hashCode();

        mPrimaryUserId = key.getPrimaryUserIdWithFallback();
        mUserIds = key.getUnorderedUserIds();
        updateMergedUserIds();

        // if there was no user id flagged as primary, use the first one
        if (mPrimaryUserId == null) {
            mPrimaryUserId = context.getString(R.string.user_id_none);
        }

        mKeyId = key.getKeyId();
        mKeyIdHex = KeyFormattingUtils.convertKeyIdToHex(mKeyId);

        // NOTE: Dont use maybe methods for now, they can be wrong.
        mRevoked = false; //key.isMaybeRevoked();
        mExpired = false; //key.isMaybeExpired();
        mFingerprintHex = KeyFormattingUtils.convertFingerprintToHex(key.getFingerprint());
        mBitStrength = key.getBitStrength();
        mCurveOid = key.getCurveOid();
        final int algorithm = key.getAlgorithm();
        mAlgorithm = KeyFormattingUtils.getAlgorithmInfo(context, algorithm, mBitStrength, mCurveOid);
    }

    public void updateMergedUserIds() {
        mMergedUserIds = new HashMap<>();
        for (String userId : mUserIds) {
            OpenPgpUtils.UserId userIdSplit = KeyRing.splitUserId(userId);

            // TODO: comment field?

            if (userIdSplit.name != null) {
                if (userIdSplit.email != null) {
                    if (!mMergedUserIds.containsKey(userIdSplit.name)) {
                        HashSet<String> emails = new HashSet<>();
                        emails.add(userIdSplit.email);
                        mMergedUserIds.put(userIdSplit.name, emails);
                    } else {
                        mMergedUserIds.get(userIdSplit.name).add(userIdSplit.email);
                    }
                } else {
                    // name only
                    mMergedUserIds.put(userIdSplit.name, new HashSet<String>());
                }
            } else {
                // fallback
                mMergedUserIds.put(userId, new HashSet<String>());
            }
        }
    }

}
