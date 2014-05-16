package appcelerator.https;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class PinningTrustManager implements X509TrustManager {

	private PublicKey publicKey;
	private X509TrustManager standardTrustManager;
	
	protected PinningTrustManager(PublicKey key) throws Exception {
		TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		factory.init((KeyStore) null);
		TrustManager[] trustmanagers = factory.getTrustManagers();
		if (trustmanagers.length == 0)
		{
			throw new NoSuchAlgorithmException("No trust manager found");
		}
		this.standardTrustManager = (X509TrustManager) trustmanagers[0];
		this.publicKey = key;

	}
	
	@Override
	public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
		this.standardTrustManager.checkClientTrusted(arg0, arg1);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
		this.standardTrustManager.checkServerTrusted(arg0, arg1);
		X509Certificate leaf = arg0[0];
		try {
			PublicKey leafKey = leaf.getPublicKey();
			if (!leafKey.equals(this.publicKey)) {
				throw new CertificateException("Leaf certificate public key does not match provided public key");
			}
		}
		catch (Throwable t) {
			throw new CertificateException(t.getMessage());
		}
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return this.standardTrustManager.getAcceptedIssuers();
	}

}
