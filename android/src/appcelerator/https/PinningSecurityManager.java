package appcelerator.https;

import java.security.PublicKey;
import java.util.HashMap;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.appcelerator.kroll.KrollProxy;
import org.appcelerator.kroll.annotations.Kroll;

import android.net.Uri;
import ti.modules.titanium.network.SecurityManagerProtocol;

@Kroll.proxy
public class PinningSecurityManager extends KrollProxy implements SecurityManagerProtocol {

	private HashMap<String, PinningTrustManager> supportedHosts = new HashMap<String, PinningTrustManager>();
	
	@Override
	public X509KeyManager[] getKeyManagers(Uri uri) {
		// Always returns null. This module does server side trust only.
		return null;
	}

	/**
	 * Returns the X509KeyManager array for the SSL Context.
	 * @param uri - The end point of the network connection
	 * @return Return array of X509KeyManager for custom client certificate management. Null otherwise.
	 */
	@Override
	public X509TrustManager[] getTrustManagers(Uri uri) {
		if (willHandleURL(uri)) {
			X509TrustManager[] tmarray = new X509TrustManager[] {supportedHosts.get(uri.getHost())};
			return tmarray;
		}
		return null;
	}

	/**
	 * Defines if the SecurityManager will provide TrustManagers and KeyManagers for SSL Context given a Uri
	 * @param uri - The end point for the network connection
	 * @return true if SecurityManagers will define SSL Context, false otherwise.
	 */
	@Override
	public boolean willHandleURL(Uri uri) {		
		if(uri != null) {
			//The Pinning Manager adds 
			return hostConfigured(uri.getHost());
		}
		return false;
	}
	
	private boolean hostConfigured(String host) {
		return supportedHosts.keySet().contains(host);
	}
	
	protected void addProfile(String host, PublicKey key) throws Exception{
		String theHost = (host == null) ? "" : host;
		
		if(theHost.length() > 0 && key != null) {
			if (!hostConfigured(theHost)) {
				supportedHosts.put(theHost, new PinningTrustManager(key));
			} else {
				throw new Exception("Duplicate host configuration.");
			}
		} else {
			throw new Exception("Invalid arguments passed to addProfile");
		}
	}

	@Override
	public String getApiName()
	{
		return "appcelerator.https.PinningSecurityManager";
	}
}
