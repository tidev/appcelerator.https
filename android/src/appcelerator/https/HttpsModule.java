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
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import org.appcelerator.kroll.KrollModule;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.titanium.TiApplication;
import org.appcelerator.titanium.util.TiConvert;
import org.appcelerator.titanium.util.TiFileHelper;
import org.appcelerator.titanium.util.TiUrl;

@Kroll.module(name = "Https", id = "appcelerator.https")
public class HttpsModule extends KrollModule
{
	// Standard Debugging variables
	protected static final String TAG = "HttpsModule";

	// Proxy variables
	private static final String PROP_URL = "url";
	private static final String PROP_TRUST_CHAIN_INDEX = "trustChainIndex";
	private static final String PROP_SERVER_CERT = "serverCertificate";
	private static final String PROP_CLIENT_CERT = "clientCertificate";
	private static final String PROP_CLIENT_PASSWORD = "clientPassword";

	public HttpsModule()
	{
		super();
	}

	@Kroll.onAppCreate
	public static void onAppCreate(TiApplication app)
	{
		// Nothing
	}

	/**
	 * Create an instance of PinningSecurityManager which implements the SecurityManagerProtocol
	 * @param args - An array of dictionaries specifying the Pinning Parameters.
	 * Each dictionary must define the following key value pairs
	 * <"url",String> - The String representing the URL of the connection end point. Must be a valid URL. The host name of the URL is used to match pinned hosts.
	 * <"serverCertificate", String> - The String representing the path to the certificate to parse. The certificate must be either DER or PEM encoded.
	 * The path is relative to the Resources directory of the application. The PublicKey portion of the certificate is used for Pinning during SSL Server Trust Handshake.
	 * @return - An instance of of the PinningSecurityManager
	 * @throws Exception - If the specified key value pair could not be parsed to retrieve a valid <Host,PublicKey> pair.
	 */
	@SuppressWarnings("rawtypes")
	@Kroll.method
	public PinningSecurityManager createX509CertificatePinningSecurityManager(Object[] args) throws Exception
	{
		PinningSecurityManager manager = new PinningSecurityManager();
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		TiFileHelper tfh = new TiFileHelper(TiApplication.getInstance());

		for (Object arg : args) {
			Object[] subargs = (Object[]) arg;
			for (Object subarg : subargs) {
				HashMap map = null;
				if (subarg instanceof HashMap) {
					map = (HashMap) subarg;
				} else {
					// TODO Spit out an error?
					continue;
				}

				InputStream is = null;
				Exception caughtException = null;

				try {
					String host = TiConvert.toString(map.get(PROP_URL));

					int trustChainIndex = TiConvert.toInt(map.get(PROP_TRUST_CHAIN_INDEX), 0);
					String serverCertPath = TiConvert.toString(map.get(PROP_SERVER_CERT));
					String clientCertPath = TiConvert.toString(map.get(PROP_CLIENT_CERT));
					String clientCertPassword = TiConvert.toString(map.get(PROP_CLIENT_PASSWORD));

					Uri hostUri = Uri.parse(host);

					TiUrl serverCertUri = new TiUrl(serverCertPath);
					is = tfh.openInputStream(serverCertUri.resolve(), false);
					Certificate serverCert = factory.generateCertificate(is);
					manager.addProfile(hostUri.getHost(), serverCert.getPublicKey(), trustChainIndex);

					if (clientCertPath != null) {
						if (is != null) {
							is.close();
						}
						TiUrl clientCertUrl = new TiUrl(clientCertPath);
						is = tfh.openInputStream(clientCertUrl.resolve(), false);
						KeyStore keyStore = KeyStore.getInstance("pkcs12");
						keyStore.load(is, clientCertPassword.toCharArray());
						manager.addKeyStore(keyStore, clientCertPassword);
					}
				} catch (Exception e) {
					caughtException = e;
				} finally {
					if (is != null) {
						try {
							is.close();
						} catch (Throwable t) {
							//Ignore
						}
						is = null;
					}
				}
				if (caughtException != null) {
					throw caughtException;
				}
			}
		}

		factory = null;
		tfh = null;

		return manager;
	}

	@Override
	public String getApiName()
	{
		return "appcelerator.https";
	}
}
