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

import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.HashMap;

import org.appcelerator.kroll.KrollDict;
import org.appcelerator.kroll.KrollModule;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.titanium.TiApplication;
import org.appcelerator.titanium.util.TiConvert;
import org.appcelerator.titanium.util.TiFileHelper;
import org.appcelerator.titanium.util.TiUrl;

import android.net.Uri;

@Kroll.module(name="https", id="appcelerator.https")
public class HttpsModule extends KrollModule
{
	// Standard Debugging variables
	private static final String TAG = "HttpsModule";
	private static final String PROP_URL = "url";
	private static final String PROP_CERT = "serverCertificate";
	
	
	public HttpsModule()
	{
		super();
	}
	
	@Kroll.onAppCreate
	public static void onAppCreate(TiApplication app)
	{
		//Nothing
	}
	
	@SuppressWarnings("rawtypes")
	@Kroll.method
	public PinningSecurityManager createX509CertificatePinningSecurityManager(HashMap[] args) throws Exception
	{
		PinningSecurityManager theManager = new PinningSecurityManager();
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		TiFileHelper tfh = new TiFileHelper(TiApplication.getInstance());
		
		for (HashMap arg : args) {
			InputStream is = null;
			Exception caughtException = null;
			
			try {
				String host = TiConvert.toString(arg.get(PROP_URL));
				String certPath = TiConvert.toString(arg.get(PROP_CERT));
				
				Uri hostUri = Uri.parse(host);
				TiUrl certUrl = new TiUrl(certPath);
				
				is = tfh.openInputStream(certUrl.resolve(), false);
				Certificate cert = factory.generateCertificate(is);
				theManager.addProfile(hostUri.getHost(), cert.getPublicKey());
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
		
		factory = null;
		tfh = null;
		
		return theManager;
	}
	
	@Override
	public String getApiName()
	{
		return "appcelerator.https";
	}
}

