/**
 * This is an example of how to use the appcelerator.https module.
 *
 * Author: Matt Langston
 * Created: 2014.04.29
 */

var https = require('appcelerator.https'),
	securityManager,
	httpClient,
	win,
	view,
	button,
	label;

win = Titanium.UI.createWindow({  
    title: 'Pin Example',
    backgroundColor: 'white'
});

view = Ti.UI.createView({
	backgroundColor: 'white',
	layout: 'vertical',
	width: Ti.UI.SIZE,
	height: Ti.UI.SIZE
});

button = Titanium.UI.createButton({
	title: 'Load',
	color: 'black',
	font: {fontSize: 20, fontFamily: 'Helvetica Neue'},
	textAlign: Ti.UI.TEXT_ALIGNMENT_CENTER
});

view.add(button);

label = Titanium.UI.createLabel({
	text: 'Status: Unknown',
	color: 'black',
	font: {fontSize: 20, fontFamily: 'Helvetica Neue'},
	textAlign: Ti.UI.TEXT_ALIGNMENT_CENTER
});

view.add(label);

win.add(view);
win.open();


/*
 * Create a Security Manager for Titanium.Network.HTTPClient that
 * authenticates a currated set of HTTPS servers. It does this by
 * "pinning" an HTTPS server's DNS name to the public key contained in
 * the X509 certificate it uses for TLS communication. The public key
 * is embedded in an app by adding this X509 certificate to the app's
 * Resources directory.
 *
 * With such a "pin" in place, the security manager will guarantee
 * that all HTTPClient connections to this HTTPS server are to a
 * server that holds the private key corresponding to the public key
 * embedded in the app, therefore authenticating the server.
 *
 * This is what prevents "Man-in-the-Middle" attack.
 *
 * This example pins two URLs.
 *
 * The first URL, https://dashboard.appcelerator.com, is pinned to the
 * public key in the X.509 certificate in the file named
 * *.appcelerator.com.cer in the app's Resources directory.
 *
 * The second URL, https://www.wellsfargo.com, is pinned to the public
 * key in the X.509 certificate in the file named
 * www.wellsfargo.com.cer in teh app's Resources directory.
 *
 * The X.509 certificate files can have any name and extension you
 * wish, but they must be in the standard DER binary format.
 */
securityManager = https.createX509CertificatePinningSecurityManager([
	{
		url: "https://dashboard.appcelerator.com",
		serverCertificate: "*.appcelerator.com.cer"
	},
	{
		url: "https://www.wellsfargo.com",
		serverCertificate: "www.wellsfargo.com.cer"
	}
]);


/*
 * Create an HTTP client the same way you always have, but pass in an
 * (optional) Security Manager. In this example, we pass in the
 * "Certificate Pinning Security Manager " that I configured above.
 */
httpClient = Ti.Network.createHTTPClient({
	
    onload: function(e) {
        Ti.API.info('MDL (onload): ' + this.responseText);
		label.text = 'Status: OK';
    },
	
    onerror: function(e) {
        Ti.API.debug('MDL (onerror):' + e.error);
		label.text = 'Status: Fail';
    },
	
    timeout : 5000				// in milliseconds
	
	// This is new.
	// securityManager: securityManager
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
httpClient.open("GET", "https://www.wellsfargo.com");

/*
 * Send the request in the same way you always have.
 */
button.addEventListener('click', function(e) {
	Titanium.API.info("httpClient.send()");
	httpClient.send();
});
