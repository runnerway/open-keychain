package org.sufficientlysecure.keychain.ui.loader;

import org.sufficientlysecure.keychain.util.Preferences;

public class CloudLoaderState implements LoaderState {

    public Preferences.CloudSearchPrefs mCloudPrefs;
    public String mServerQuery;

    public CloudLoaderState(String serverQuery, Preferences.CloudSearchPrefs cloudPrefs) {
        mServerQuery = serverQuery;
        mCloudPrefs = cloudPrefs;
    }

}
