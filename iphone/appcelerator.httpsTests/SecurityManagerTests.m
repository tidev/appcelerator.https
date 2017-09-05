//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "AbstractBaseTest.h"
#import "SecurityManager.h"
#import "PinnedURL.h"
#import "AppceleratorHttps.h"

@interface SecurityManagerTests : AbstractBaseTest

@end

@implementation SecurityManagerTests

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

    NSURL *url1 = [NSURL URLWithString:@"https://server1.prod.ace.appcelerator.com"];
    NSURL *url2 = [NSURL URLWithString:@"https://server2.prod.ace.appcelerator.com"];
    NSLog(@"host = %@", url1.host);
    NSLog(@"host = %@", url2.host);
    
    NSMutableSet *pinnedUrlSet = [NSMutableSet set];
    [pinnedUrlSet addObject:[PinnedURL pinnedURLWithURL:url1 andPublicKey:certificate1.publicKey]];
    [pinnedUrlSet addObject:[PinnedURL pinnedURLWithURL:url2 andPublicKey:certificate2.publicKey]];
    
    XCTAssertEqual(2, pinnedUrlSet.count);
    
    SecurityManager *securityManager = [SecurityManager securityManagerWithPinnedUrlSet:pinnedUrlSet];
    XCTAssertNotNil(securityManager);
}

@end
