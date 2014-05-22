/**
 * These are the functional tests for the appcelerator.https module.
 *
 * Author: Matt Langston
 * Created: 2014.04.29
 */
require('ti-mocha');
var should = require('should');

describe('appcelerator.https', function() {
	var https = require('appcelerator.https'),
		securityManager,
		httpClient;
	
	beforeEach(function() {
		httpClient = Ti.Network.createHTTPClient({
			
			onload: function(e) {
				Ti.API.info('MDL (onload): ' + this.responseText);
			},
			
			onerror: function(e) {
				Ti.API.debug('MDL (onerror):' + e.error);
			},
			
			timeout : 5000		// in milliseconds
			
			// This is new.
			// securityManager: securityManager
		});
	});
	
    it('httpClient exists', function() {
        should.exist(httpClient);
    });
	
    it('httpClient can open an HTTPS URL', function() {
		httpClient.open("GET", "https://dashboard.appcelerator.com");
		httpClient.send();
    });
	
    it('securityManager exists', function(){
        should.exist(securityManager);
    });
	
    it('securityManager has pinnedCertificateList property', function() {
        should(securityManager).have.property('pinnedCertificateList');;
    });
});

// run the tests
mocha.run();
