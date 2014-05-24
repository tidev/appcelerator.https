/**
 * Appcelerator.Https Module - Authenticate server in HTTPS
 * connections made by TiHTTPClient.
 *
 * Copyright (c) 2014 by Appcelerator, Inc. All Rights Reserved.
 *
 * Licensed under the terms of the Appcelerator Commercial License.
 * Please see the LICENSE included with this distribution for details.
 */

package appcelerator.https;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import ti.modules.titanium.network.HTTPClientProxy;
import android.net.Uri;

public class PinningTrustManager implements X509TrustManager {

	private Map<String, PublicKey> supportedHosts;
	private HTTPClientProxy proxy;
	private X509TrustManager standardTrustManager;
	
	/**
	 * Constructor for the PinningTrustManager.
	 * @param proxy - The HTTPClientProxy representing this network connection.
	 * @param supportedHosts - The supported configurations for which PublicKey Pinning must be performed.
	 * @throws Exception - If a standard Trustmanager could not be instantiated.
	 */
	protected PinningTrustManager(HTTPClientProxy proxy, Map<String, PublicKey> supportedHosts) throws Exception {
		TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		factory.init((KeyStore) null);
		TrustManager[] trustmanagers = factory.getTrustManagers();
		if (trustmanagers.length == 0)
		{
			throw new NoSuchAlgorithmException("no trust manager found");
		}
		this.standardTrustManager = (X509TrustManager) trustmanagers[0];
		this.proxy = proxy;
		this.supportedHosts = (supportedHosts == null) ? new HashMap<String, PublicKey>() : supportedHosts;
	}
	
	@Override
	public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
		this.standardTrustManager.checkClientTrusted(arg0, arg1);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
		this.standardTrustManager.checkServerTrusted(arg0, arg1);
		
		/**
		 * If the HTTPClient proxy is currently connected to a Uri with a configured host, compare the leaf certificate
		 * in the chain with the configured PublicKey. Throws a Certificate Exception if the keys do not match.
		 */
		if (this.proxy != null) {
			boolean hostPinned = false;
			String host = "";
			String curLocation = proxy.getLocation();
			try {
				Uri uri = Uri.parse(curLocation);
				host = uri.getHost();
				hostPinned = hostConfigured(host);
				
			} catch (Exception e) {
				hostPinned = false;
			}
			
			if (hostPinned) {
				X509Certificate leaf = arg0[0];
				PublicKey leafKey = leaf.getPublicKey();
				PublicKey compareKey = supportedHosts.get(host);
				if (!leafKey.equals(compareKey)) {
					throw new CertificateException("Leaf certificate could not be verified with provided public key");
				}
			}
		}

	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return this.standardTrustManager.getAcceptedIssuers();
	}
	
	private boolean hostConfigured(String host) {
		return supportedHosts.keySet().contains(host);
	}
}
