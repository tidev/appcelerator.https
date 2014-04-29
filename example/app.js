/**
 * This is an example of how to use the appcelerator.https module.
 *
 * Author: Matt Langston
 * Created: 2014.04.29
 */

var https = require('appcelerator.https'),
	securityManager,
	httpClient;

/*
 * Create a Security Manager for Titanium.Network.HTTPClient that
 * authenticates a currated set of HTTPS servers. It does this by
 * "pinning" an HTTPS server's URL to it's public key which I have
 * embedded in my app. The security manager will guarantee that all
 * HTTPClient connections to this URL are to a server that holds the
 * private key corresponding to the public key embedded in my app,
 * therefore authenticating the server.
 *
 * This is what prevents the "Man-in-the-Middle" attack.
 *
 * In this example I am pinning two URLs.
 *
 * The first URL, https://dashboard.appcelerator.com, is pinned to the
 * public key in the X.509 certificate in the file named
 * dashboard.appcelerator.com.pem in my App's Resources directory.
 *
 * The second URL, https://www.wellsfargo.com, is pinned to the public
 * key in the X.509 certificate in the file named wellsfargo.der in my
 * App's Resources directory.
 *
 * The X.509 certificate files can have any name and extension you
 * wish, but they must be in either the standard PEM textual format or
 * the DER binary format.
 */
securityManager = https.createCertificatePinningSecurityManager([
	{
		url: "https://dashboard.appcelerator.com",
		serverCertificate: "dashboard.appcelerator.com.pem"
	},
	{
		url: "https://www.wellsfargo.com",
		serverCertificate: "wellsfargo.der"
	}
]);


/*
 * Create an HTTP client the same way you always have, but pass in an
 * (optional) Security Manager. In this example, we pass in the
 * "Certificate Pinning Security Manager " that I configured above.
 */
httpClient = Ti.Network.createHTTPClient({
	
    onload: function(e) {
        Ti.API.info("Received text: " + this.responseText);
    },
	
    onerror: function(e) {
        Ti.API.debug(e.error);
    },
	
    timeout : 5000,				// in milliseconds

	// This is new.
	securityManager: securityManager
});


/*
 * Prepare and use the HTTPS connection in the same way you always
 * have and the Security Manager will authenticate all servers for
 * which it was configured before any communication happens.
 *
 * In this example, the server with the DNS name
 * dashboard.appcelerator.com will be authenticated before any
 * communications happens. A Security Exception it thrown if
 * authentication fails.
 */
httpClient.open("GET", "https://dashboard.appcelerator.com");

/*
 * Send the request in the same way you always have.
 */
httpClient.send();
