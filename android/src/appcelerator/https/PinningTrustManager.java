/**
 * Appcelerator.Https Module - Authenticate server in HTTPS
 * connections made by TiHTTPClient.
 *
 * Copyright (c) 2014-2017 by Appcelerator, Inc. All Rights Reserved.
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
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import ti.modules.titanium.network.HTTPClientProxy;

import android.net.Uri;

public class PinningTrustManager implements X509TrustManager {

	private List<PinnedHost> supportedHosts;
	private HTTPClientProxy proxy;
	private X509TrustManager standardTrustManager;
	private boolean requireCertificate = false;

	/**
	 * Constructor for the PinningTrustManager.
	 * @param proxy - The HTTPClientProxy representing this network connection.
	 * @param supportedHosts - The supported configurations for which PublicKey Pinning must be performed.
	 * @throws Exception - If a standard Trustmanager could not be instantiated.
	 */
	protected PinningTrustManager(HTTPClientProxy proxy, List<PinnedHost> supportedHosts, boolean requireCertificate) throws Exception {
		TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		factory.init((KeyStore) null);
		TrustManager[] trustmanagers = factory.getTrustManagers();
		if (trustmanagers.length == 0) {
			throw new NoSuchAlgorithmException("No trust-manager found");
		}
		this.standardTrustManager = (X509TrustManager) trustmanagers[0];
		this.proxy = proxy;
		this.supportedHosts = (supportedHosts == null) ? new ArrayList<PinnedHost>() : supportedHosts;
		this.requireCertificate = requireCertificate;
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		this.standardTrustManager.checkClientTrusted(chain, authType);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		this.standardTrustManager.checkServerTrusted(chain, authType);		
		/**
		 * If the HTTPClient proxy is currently connected to a Uri with a configured host, compare the certificate
		 * in the chain with the configured PublicKey. Throws a Certificate Exception if the keys do not match.
		 */
		if (this.proxy != null) {
			boolean hostPinned = false;
			String host = "";
			String curLocation = proxy.getLocation();
			try {
				Uri uri = Uri.parse(curLocation);
				host = uri.getHost();
				hostPinned = PinningUtils.hasMatchingHost(host, supportedHosts);
			} catch (Exception e) {
				hostPinned = false;
			}

			if (hostPinned || requireCertificate) {
				boolean certificateMatches = false;				
				List<PinnedHost> matchingEntries = PinningUtils.getMatchingPinnedHosts(host, supportedHosts);			
				for(PinnedHost entry : matchingEntries) {
					X509Certificate leaf = chain[entry.trustChainIndex];
					PublicKey leafKey = leaf.getPublicKey();
					PublicKey compareKey = entry.publicKey;
					if (leafKey.equals(compareKey)) {
						certificateMatches = true;
					}					
				}
								
				if(!certificateMatches) {
					throw new CertificateException("Certificate could not be verified with provided public key");
				}
			}
		}

	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return this.standardTrustManager.getAcceptedIssuers();
	}
}
