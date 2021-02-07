/**
 * Appcelerator.Https Module - Authenticate server in HTTPS
 * connections made by TiHTTPClient.
 *
 * Copyright (c) 2014-2017 by Axway, Inc. All Rights Reserved.
 *
 * Licensed under the terms of the Appcelerator Commercial License.
 * Please see the LICENSE included with this distribution for details.
 */
package appcelerator.https;

import android.net.Uri;
import java.security.KeyStore;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import org.appcelerator.kroll.KrollProxy;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.kroll.common.Log;
import ti.modules.titanium.network.HTTPClientProxy;
import ti.modules.titanium.network.SecurityManagerProtocol;

@Kroll.proxy
public class PinningSecurityManager extends KrollProxy implements SecurityManagerProtocol
{

  private Map<String, HashSet<PublicKey>> supportedHosts = new HashMap<String, HashSet<PublicKey>>();
	private Map<KeyStore, String> keyStores = new HashMap<KeyStore, String>();
	private int trustChainIndex = 0;

	/**
	 * Returns the X509KeyManager array for the SSL Context.
	 * @param uri - The end point of the network connection
	 * @return Return array of X509KeyManager for custom client certificate management. Null otherwise.
	 */
	@Override
	public X509KeyManager[] getKeyManagers(HTTPClientProxy proxy)
	{
		List<X509KeyManager> managers = new ArrayList<X509KeyManager>();

		for (Map.Entry<KeyStore, String> entry : keyStores.entrySet()) {
			KeyStore keyStore = entry.getKey();
			String password = entry.getValue();
			try {
				KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
				factory.init(keyStore, password.toCharArray());

				for (KeyManager manager : factory.getKeyManagers()) {
					managers.add((X509KeyManager) manager);
				}
			} catch (Exception e) {
				Log.e(HttpsModule.TAG, "KeyManager exception: " + e);
				return null;
			}
		}

		return managers.toArray(new X509KeyManager[managers.size()]);
	}

	/**
	 * Returns the X509TrustManager array for the SSL Context.
	 * @param uri - The end point of the network connection
	 * @return Return array of X509TrustManager for custom client certificate management. Null otherwise.
	 */
	@Override
	public X509TrustManager[] getTrustManagers(HTTPClientProxy proxy)
	{
		try {
			PinningTrustManager tm = new PinningTrustManager(proxy, supportedHosts, trustChainIndex);
			return new X509TrustManager[] { tm };
		} catch (Exception e) {
			Log.e(HttpsModule.TAG, "Unable to create PinningTrustManager. Returning null.", e);
			return null;
		}
	}

	/**
	 * Defines if the SecurityManager will provide TrustManagers and KeyManagers for SSL Context given a Uri
	 * @param uri - The end point for the network connection. The host of this Uri must be one of the configured hosts for the SecurityManager.
	 * @return true if SecurityManagers will define SSL Context, false otherwise.
	 */
	@Override
	public boolean willHandleURL(Uri uri)
	{
		if (uri == null) {
			return false;
		}
		return hostConfigured(uri.getHost());
	}

	/**
	 * Adds the <Host,PublicKey> pair to list of supported configurations.
	 * @param host - String representing the host portion of supported Uris
	 * @param publicKey - The PublicKey against which the server certificate will be pinned.
	 * @param trustChainIndex - The index of the trust-chain certificate to validate against.
	 * @throws Exception - If the arguments are invalid or if the given host is already added as a supported configuration.
	 */
	protected void addProfile(String host, PublicKey key, int index) throws Exception
	{
		if (key != null) {
      String map_key = host.toLowerCase(Locale.ENGLISH);
			if (!hostConfigured(host)) {
        supportedHosts.put(map_key, new HashSet<PublicKey>());
			}
      supportedHosts.get(map_key).add(key);
			trustChainIndex = index;
		} else {
			throw new Exception("Invalid arguments passed to addProfile");
		}
	}

	/**
	 * Adds the key store to the key manager.
	 * @param keyStore - Key store containing the client private key.
	 * @param password - The password for the key store.
	 */
	protected void addKeyStore(KeyStore keyStore, String password)
	{
		if (!this.keyStores.keySet().contains(keyStore)) {
			this.keyStores.put(keyStore, password);
		}
	}

	/**
	 * Returns if the host is part of the supported configurations.
	 * @param host - String representing the host portion of supported Uris
	 * @return - True if the host is configured, false otherwise.
	 */
	private boolean hostConfigured(String host)
	{
		String theHost = (host == null) ? "" : host;
		return supportedHosts.keySet().contains(theHost.toLowerCase(Locale.ENGLISH));
	}

	/**
	 * Returns the trust-chain index.
	 * @return - The index representing the trust-chain index-position.
	 */
	public int getTrustChainIndex()
	{
		return trustChainIndex;
	}

	@Override
	public String getApiName()
	{
		return "appcelerator.https.PinningSecurityManager";
	}
}
