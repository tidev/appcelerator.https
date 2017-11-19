/**
 * This is an example of how to use the appcelerator.https module.
 */
var https = require('appcelerator.https');

/*
 * Create a Security Manager for Titanium.Network.HTTPClient that
 * authenticates a currated set of HTTPS servers. It does this by
 * 'pinning' an HTTPS server's DNS name to the public key contained in
 * the X509 certificate it uses for TLS communication. The public key
 * is embedded in an app by adding this X509 certificate to the app's
 * Resources directory.
 *
 * With such a 'pin' in place, the security manager will guarantee
 * that all HTTPClient connections to this HTTPS server are to a
 * server that holds the private key corresponding to the public key
 * embedded in the app, therefore authenticating the server.
 *
 * This is what prevents 'Man-in-the-Middle' attack.
 *
 * This example pins two URLs.
 *
 * The first URL, https://www.americanexpress.com, is pinned to the
 * public key in the X.509 certificate in the file named
 * wellsfargo.cer. This is intentionally an incorrect configuration.
 * Connections to https://www.americanexpress.com must fail since the
 * public key presented by the host will not match the configuration of the
 * security manager
 *
 * The second URL, https://www.wellsfargo.com, is pinned to the public
 * key in the X.509 certificate in the file named
 * wellsfargo.cer. This is configured correctly. Connections to
 * https://www.wellsfargo.com must succeed. Note that these request redirect.
 * The redirected request is not handled by the security manager since it is
 * not configured but will succeed if the system is able to validate the
 * certificate chain presented by the redirected host.
 *
 * The X.509 certificate files can have any name and extension you
 * wish, but they must be in the standard DER binary format.
 */
var securityManager = https.createX509CertificatePinningSecurityManager([
  {
    url: 'https://www.americanexpress.com',
    serverCertificate: 'wellsfargo.cer'
  },
  {
    url: 'https://www.wellsfargo.com',
    serverCertificate: 'SC3.der',
    trustChainIndex: 1
  }
]);

var win = Titanium.UI.createWindow({
  title: 'Pin Example',
  backgroundColor: 'white'
});

var view = Ti.UI.createView({
  backgroundColor: 'white',
  layout: 'vertical',
  top: 20
});

var button1 = Titanium.UI.createButton({
  title: 'Load wellsfargo',
  color: 'green',
  top: 20
});

var button2 = Titanium.UI.createButton({
  title: 'Load americanexpress',
  color: 'red',
  top: 20
});

var button3 = Titanium.UI.createButton({
  title: 'Load appcelerator',
  color: 'blue',
  top: 20
});

var label1 = Titanium.UI.createLabel({
  text: 'Desc:',
  color: 'black',
  top: 20
});

var label2 = Titanium.UI.createLabel({
  text: 'Status:',
  color: 'black',
  top: 20
});

view.add(button1);
view.add(button2);
view.add(button3);
view.add(label1);
view.add(label2);

win.add(view);
win.open();

/*
 * Create an HTTP client the same way you always have, but pass in an
 * (optional) Security Manager. In this example, we pass in the
 * 'Certificate Pinning Security Manager' that was configured above.
 */

function getXHR(url) {
  var xhr = Ti.Network.createHTTPClient({
    onload: function(e) {
      label2.text = 'onload called. Request succeeded';
    },
    onerror: function(e) {
      label2.text = 'onerror called. Request failed.';
    },
    timeout: 30000,
    securityManager: securityManager
  });

  xhr.open('GET', url);

  return xhr;
}

var wf = 'https://www.wellsfargo.com';
var amex = 'https://www.americanexpress.com';
var appc = 'https://dashboard.appcelerator.com';

button1.addEventListener('click', function(e) {
  var xhr = getXHR(wf);
  label1.text =
    'SecurityManager is configured correctly for this request. Request must succeed. ';
  label1.color = 'green';
  label2.text = 'Desc:';
  xhr.send();
});

button2.addEventListener('click', function(e) {
  var xhr = getXHR(amex);
  label1.text =
    'SecurityManager is configured incorrectly for this request. Request must fail. ';
  label1.color = 'red';
  label2.text = 'Desc:';
  xhr.send();
});

button3.addEventListener('click', function(e) {
  var xhr = getXHR(appc);
  label1.text =
    'SecurityManager does not participate in the validation of this request. Request should succeed. ';
  label1.color = 'blue';
  label2.text = 'Desc:';
  xhr.send();
});
