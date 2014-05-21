package appcelerator.https;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.appcelerator.kroll.KrollProxy;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.kroll.common.Log;

import android.net.Uri;
import ti.modules.titanium.network.HTTPClientProxy;
import ti.modules.titanium.network.SecurityManagerProtocol;

@Kroll.proxy
public class PinningSecurityManager extends KrollProxy implements SecurityManagerProtocol {

	private Map<String, PublicKey> supportedHosts = new HashMap<String, PublicKey>();
	@Override
	public X509KeyManager[] getKeyManagers(HTTPClientProxy proxy) {
		// Always returns null. This module does server side trust only.
		return null;
	}
	
	/**
	 * Returns the X509KeyManager array for the SSL Context.
	 * @param uri - The end point of the network connection
	 * @return Return array of X509KeyManager for custom client certificate management. Null otherwise.
	 */
	@Override
	public X509TrustManager[] getTrustManagers(HTTPClientProxy proxy) {
		try {
			PinningTrustManager tm = new PinningTrustManager(proxy, supportedHosts);
			return new X509TrustManager[]{tm};
		} catch (Exception e) {
			Log.e(HttpsModule.TAG, "Unable to create PinningTrustManager. Returning null.", e);
			return null;
		}
	}

	/**
	 * Defines if the SecurityManager will provide TrustManagers and KeyManagers for SSL Context given a Uri
	 * @param uri - The end point for the network connection
	 * @return true if SecurityManagers will define SSL Context, false otherwise.
	 */
	@Override
	public boolean willHandleURL(Uri uri) {		
		if(uri != null) {
			return hostConfigured(uri.getHost());
		}
		return false;
	}
	
	protected void addProfile(String host, PublicKey key) throws Exception{
		String theHost = (host == null) ? "" : host;
		
		if(theHost.length() > 0 && key != null) {
			if (!hostConfigured(theHost)) {
				supportedHosts.put(theHost, key);
			} else {
				throw new Exception("Duplicate host configuration.");
			}
		} else {
			throw new Exception("Invalid arguments passed to addProfile");
		}
	}
	
	private boolean hostConfigured(String host) {
		return supportedHosts.keySet().contains(host);
	}

	@Override
	public String getApiName()
	{
		return "appcelerator.Https.PinningSecurityManager";
	}
}
