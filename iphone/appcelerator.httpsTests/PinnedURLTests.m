//
//  PinnedURLTests.m
//  CertificatePinningSecurityManager
//
//  Created by Matt Langston on 5/20/14.
//  Copyright (c) 2014 Appcelerator. All rights reserved.
//

#import "AbstractBaseTest.h"
#import "PinnedURL.h"

@interface PinnedURLTests : AbstractBaseTest
@end

@implementation PinnedURLTests

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

    NSURL *url = [NSURL URLWithString:@"https://71616668e3201581811ab36226837d53409a9ab0.prod.ace.appcelerator.com"];
    NSLog(@"host = %@", url.host);
    
    PinnedURL *pinnedURL = [PinnedURL PinnedURLWithURL:url andPublicKey:publicKey];
    XCTAssertNotNil(pinnedURL);
    
    XCTAssertEqualObjects(@"71616668e3201581811ab36226837d53409a9ab0.prod.ace.appcelerator.com", pinnedURL.host);
    XCTAssertEqualObjects(publicKey, pinnedURL.publicKey);
    XCTAssertEqualObjects(url, pinnedURL.url);
}

@end
