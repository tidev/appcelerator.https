const ANDROID = (Ti.Platform.osname === 'android');
const IOS = (Ti.Platform.osname === 'iphone' || Ti.Platform.osname === 'ipad');

describe('appcelerator.https', () => {
	let https;
	it('can be required', () => {
		https = require('appcelerator.https');

		expect(https).toBeDefined();
	});

	it('.apiName', () => {
		expect(https.apiName).toBe('Appcelerator.HTTPS');
	});

	describe('methods', () => {
		describe('#createX509CertificatePinningSecurityManager()', () => {
			it('is a Function', () => {
				expect(https.createX509CertificatePinningSecurityManager).toEqual(jasmine.any(Function));
			});

			it('works with configured cert', (done) => {
				const securityManager = https.createX509CertificatePinningSecurityManager([
					{
						url: 'https://www.wellsfargo.com',
						serverCertificate: 'wellsfargo.cer'
					}
				]);

				const xhr = Ti.Network.createHTTPClient({
					onload: _e => done(),
					onerror: _e => done(new Error('Expected request to succeed')),
					timeout: 30000,
					securityManager
				});
			
				xhr.open('GET', 'https://www.wellsfargo.com');
				xhr.send();
			});

			it('fails with wrong cert', (done) => {
				const securityManager = https.createX509CertificatePinningSecurityManager([
					{
						url: 'https://www.americanexpress.com',
						serverCertificate: 'wellsfargo.cer'
					}
				]);

				const xhr = Ti.Network.createHTTPClient({
					onload: _e => done(new Error('Expected request to fail, but it did not')),
					onerror: _e => done(),
					timeout: 30000,
					securityManager
				});
			
				xhr.open('GET', 'https://www.americanexpress.com');
				xhr.send();
			});

			it('works for trustChainIndex', (done) => {
				const securityManager = https.createX509CertificatePinningSecurityManager([
					{
						url: 'https://www.wellsfargo.com',
						serverCertificate: 'SC3.der',
						trustChainIndex: 1
					}
				]);

				const xhr = Ti.Network.createHTTPClient({
					onload: _e => done(),
					onerror: _e => done(new Error('Expected request to succeed')),
					timeout: 30000,
					securityManager
				});
			
				xhr.open('GET', 'https://www.wellsfargo.com');
				xhr.send();
			});

			it('request succeeds when url not configured', (done) => {
				const securityManager = https.createX509CertificatePinningSecurityManager([
					{
						url: 'https://www.wellsfargo.com',
						serverCertificate: 'wellsfargo.cer'
					}
				]);

				const xhr = Ti.Network.createHTTPClient({
					onload: _e => done(),
					onerror: _e => done(new Error('Expected request to succeed')),
					timeout: 30000,
					securityManager
				});
			
				xhr.open('GET', 'https://dashboard.appcelerator.com');
				xhr.send();
			});
		});
	});
});
