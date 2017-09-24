package appcelerator.https;

import java.security.PublicKey;

public class PinnedHost {

	String host;
	PublicKey publicKey;
	int trustChainIndex;
	
	public PinnedHost(String host, PublicKey publicKey, int trustChainIndex) {
		this.host = host;
		this.publicKey = publicKey;
		this.trustChainIndex = trustChainIndex;
	}
}
