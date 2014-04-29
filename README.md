* ti.https

This Titanium module for both iOS and Android will prevent a
"Man-in-the-Middle" attack when used with the standard
Ti.Network.createHTTPClient.


The following example does a simple secure GET request that prevents a
"Man-in-the-Middle" attack.

```JavaScript
/**
 * This is an example of how to use the appcelerator.https module.
 */

var https = require('appcelerator.https'),
	httpClient,
	serverCertificateFile,
	secureURL;

/*
 * Create an HTTP client the same way you always have.
 */
httpClient = Ti.Network.createHTTPClient({
	
    onload: function(e) {
        Ti.API.info("Received text: " + this.responseText);
    },
	
    onerror: function(e) {
        Ti.API.debug(e.error);
    },
	
    timeout : 5000				// in milliseconds
});

/*
 * Obtain the file containing your server's X.509 certificate that you
 * bundled with your app. This file can have any name and extension
 * you wish, but it must be in either the standard PEM textual format
 * or the DER binary format.
 *
 * Here I have named my server's certificate
 * "dashboard.appcelerator.com.pem" and placed it in my app's
 * Resources directory.
 */
serverCertificateFile = Ti.Filesystem.getFile(Ti.Filesystem.resourcesDirectory, 'dashboard.appcelerator.com.pem');

/*
 * Next create an https.SecureURL that "pins" an HTTPS server to the
 * TLS (or SSL) certificate that you bundled with your app.
 */
secureURL = https.createSecureURL({
	url: "https://dashboard.appcelerator.com",
	serverCertificateFile: serverCertificateFile
});

/*
 * Prepare the connection in the same way you always have, except you
 * pass in the secureURL object for the second parameter instead of a
 * string that specifies the URL. This guarantees that the HTTPS
 * server you communicate with has the same public key as the one from
 * the SSL certificate that you bundled in your app.
 *
 * The use of the https.SecureURL is what prevents the
 * Man-in-the-Middle attack. If you were to just pass in a string URL
 * then there is no guarantee that you are communicating with a server
 * that you trust.
 */
httpClient.open("GET", secureURL);

/*
 * Send the request in the same way you always have.
 */
httpClient.send();

/*
 * This is a convenience function that finds an X.509 server
 * certificate by file name from your app's Resources directory.
 */
// https.findServerCertificateByFileName();
```



This module imlpements the Enterprise module portion for "TLS
Certificate Pinning", specifically
[MOD-1706](https://jira.appcelerator.org/browse/MOD-1706) and
[MOD-1707](https://jira.appcelerator.org/browse/MOD-1707).

These are all of the tickets associated with this feature.

* [TIMOB-16856\]](https://jira.appcelerator.org/browse/TIMOB-16856)  (Story) Prevent HTTPS "Man-in-the-Middle" attack
* [TIMOB-16855\]](https://jira.appcelerator.org/browse/TIMOB-16855)  (New Feature) iOS: Support custom NSURLConnectionDelegate in TiHTTPRequest
* [TIMOB-16857\]](https://jira.appcelerator.org/browse/TIMOB-16857)  (New Feature) Android: Support custom TLS Server Trust evaluation for TiHTTPRequest
* [MOD-1706\]](https://jira.appcelerator.org/browse/MOD-1706)  (Module) iOS: Authenticate server in HTTPS connections made by TiHTTPRequest
* [MOD-1707\]](https://jira.appcelerator.org/browse/MOD-1707)  (Module) Android: Authenticate server in HTTPS connections made by TiHTTPClient
