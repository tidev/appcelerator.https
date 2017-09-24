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

import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.HashMap;

import org.appcelerator.kroll.KrollModule;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.kroll.common.Log;
import org.appcelerator.titanium.TiApplication;
import org.appcelerator.titanium.util.TiConvert;
import org.appcelerator.titanium.util.TiFileHelper;
import org.appcelerator.titanium.util.TiUrl;

import android.net.Uri;

@Kroll.module(name="Https", id="appcelerator.https")
public class HttpsModule extends KrollModule
{
	// Standard Debugging variables
	protected static final String TAG = "HttpsModule";
    
	// Proxy variables
	private static final String PROP_URL = "url";
	private static final String PROP_CERT = "serverCertificate";
	private static final String PROP_TRUST_CHAIN_INDEX = "trustChainIndex";
	private boolean requireCertificate = false;
	
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
	 * Set flag if certificate pinning is required for all urls
	 * @param requireCertificate - Boolean if certificate pinning is required 
	 */
	@Kroll.method
	public void requireCertificatePinning(boolean requireCertificate) 
	{
		this.requireCertificate = requireCertificate;
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
		PinningSecurityManager theManager = new PinningSecurityManager();
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
					String certPath = TiConvert.toString(map.get(PROP_CERT));
					int trustChainIndex = TiConvert.toInt(map.get(PROP_TRUST_CHAIN_INDEX), 0);
					
					Uri hostUri = Uri.parse(host);
					TiUrl certUrl = new TiUrl(certPath);

					is = tfh.openInputStream(certUrl.resolve(), false);
					Certificate cert = factory.generateCertificate(is);
					theManager.addProfile(hostUri.getHost(), cert.getPublicKey(), trustChainIndex);
				}
				catch (Exception e) {
					caughtException = e;
				}
				finally
				{
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
		
		//set flag to configure if certificate pinning is required for all urls
		theManager.requireCertificatePinning(requireCertificate);
		return theManager;
	}

	@Override
	public String getApiName()
	{
		return "appcelerator.https";
	}
}
