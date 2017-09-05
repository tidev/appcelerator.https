//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "AbstractBaseTest.h"
#import "PublicKey.h"
#import "AppceleratorHttps.h"

@interface PublicKeyTests : AbstractBaseTest
@end

@implementation PublicKeyTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testDesignatedInitializer
{
    NSURL *certificateURL = self.certificateURLDict[@"*.prod.ace.appcelerator.com-1"];
    XCTAssertNotNil(certificateURL);
    
    X509Certificate *certificate = [X509Certificate x509CertificateWithURL:certificateURL andTrustChainIndex:0];
    XCTAssertNotNil(certificate);

    PublicKey *publicKey = [PublicKey publicKeyWithX509Certificate:certificate];
    XCTAssertNotNil(publicKey);
}

- (void)testEqual
{
    NSURL *certificateURL1 = self.certificateURLDict[@"*.prod.ace.appcelerator.com-1"];
    NSURL *certificateURL2 = self.certificateURLDict[@"*.prod.ace.appcelerator.com-2"];
    
    XCTAssertNotNil(certificateURL1);
    XCTAssertNotNil(certificateURL2);
    
    X509Certificate *certificate1 = [X509Certificate x509CertificateWithURL:certificateURL1 andTrustChainIndex:0];
    X509Certificate *certificate2 = [X509Certificate x509CertificateWithURL:certificateURL2 andTrustChainIndex:0];
    
    XCTAssertNotNil(certificate1);
    XCTAssertNotNil(certificate2);

    XCTAssertNotNil(certificate1.publicKey);
    XCTAssertNotNil(certificate2.publicKey);
    
    NSLog(@"publicKey1 = %@", certificate1.publicKey);
    NSLog(@"publicKey2 = %@", certificate2.publicKey);
    
//    XCTAssertEqualObjects(publicKey1, publicKey2);
}

@end
