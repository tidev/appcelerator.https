//
//  PublicKeyTests.m
//  CertificatePinningSecurityManager
//
//  Created by Matt Langston on 5/19/14.
//  Copyright (c) 2014 Appcelerator. All rights reserved.
//

#import "AbstractBaseTest.h"
#import "PublicKey.h"

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
    
    X509Certificate *certificate = [X509Certificate X509CertificateWithURL:certificateURL];
    XCTAssertNotNil(certificate);

    PublicKey *publicKey = [PublicKey PublicKeyWithX509Certificate:certificate];
    XCTAssertNotNil(publicKey);
}

- (void)testEqual
{
    NSURL *certificateURL1 = self.certificateURLDict[@"*.prod.ace.appcelerator.com-1"];
    NSURL *certificateURL2 = self.certificateURLDict[@"*.prod.ace.appcelerator.com-2"];
    
    XCTAssertNotNil(certificateURL1);
    XCTAssertNotNil(certificateURL2);
    
    X509Certificate *certificate1 = [X509Certificate X509CertificateWithURL:certificateURL1];
    X509Certificate *certificate2 = [X509Certificate X509CertificateWithURL:certificateURL2];
    
    XCTAssertNotNil(certificate1);
    XCTAssertNotNil(certificate2);

    PublicKey *publicKey1 = [PublicKey PublicKeyWithX509Certificate:certificate1];
    PublicKey *publicKey2 = [PublicKey PublicKeyWithX509Certificate:certificate2];

    XCTAssertNotNil(publicKey1);
    XCTAssertNotNil(publicKey2);
    
    NSLog(@"publicKey1 = %@", publicKey1);
    NSLog(@"publicKey2 = %@", publicKey2);
    
//    XCTAssertEqualObjects(publicKey1, publicKey2);
}

@end
