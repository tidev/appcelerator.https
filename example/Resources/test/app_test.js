var should = require('should');

module.exports = function(securityManager, httpClient) {
	
    describe('app.js', function() {
		
        describe('#httpClient', function() {
			
            it('exists', function() {
                should.exist(httpClient);
            });
			
            it('can open an HTTP URL', function() {
            });
			
        });
		
        describe('#securityManager', function() {
			
            it('exists', function(){
                should.exist(securityManager);
            });
			
            it('has pinnedCertificateList property', function() {
                should(securityManager).have.property('pinnedCertificateList');;
            });
        });
		
    });
	
    // run the tests
    mocha.run();
};
