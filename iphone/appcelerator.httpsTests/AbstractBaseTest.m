//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "AbstractBaseTest.h"

@interface AbstractBaseTest ()
@end

@implementation AbstractBaseTest

- (void)setUp
{
  [super setUp];

  // Populate the certificateURLDict property for the test cases.

  // The test bundle whose tests are currently running. See
  // https://devforums.apple.com/message/880843#880843
  NSBundle *mainBundle = [NSBundle bundleForClass:[self class]];

  NSMutableDictionary *certificateURLDict = [NSMutableDictionary dictionary];

  NSMutableArray *certificateBaseNames = [NSMutableArray array];
  [certificateBaseNames addObject:@"*.prod.ace.appcelerator.com-1"];
  [certificateBaseNames addObject:@"*.prod.ace.appcelerator.com-2"];
  for (NSString *certificateBaseName in certificateBaseNames) {
    NSURL *certificateURL = [mainBundle URLForResource:certificateBaseName withExtension:@"cer"];
    certificateURLDict[certificateBaseName] = certificateURL;
  }

  _certificateURLDict = [NSDictionary dictionaryWithDictionary:certificateURLDict];
}

- (void)tearDown
{
  // Put teardown code here. This method is called after the invocation of each test method in the class.
  [super tearDown];
}

- (void)testBundleContainsCertificates
{
  NSURL *certificateURL1 = self.certificateURLDict[@"*.prod.ace.appcelerator.com-1"];
  NSURL *certificateURL2 = self.certificateURLDict[@"*.prod.ace.appcelerator.com-2"];

  XCTAssertNotNil(certificateURL1);
  XCTAssertNotNil(certificateURL2);

  //    NSLog(@"certificateURL1 = %@", certificateURL1);
  //    NSLog(@"certificateURL2 = %@", certificateURL2);

  XCTAssertNotEqualObjects(certificateURL1, certificateURL2);
}

- (void)testNSURL
{
  NSURL *url1 = [NSURL URLWithString:@"https://www.foo.com"];
  NSURL *url2 = [NSURL URLWithString:@"HTTPS://WWW.FOO.COM"];

  XCTAssertNotNil(url1);
  XCTAssertNotNil(url2);

  //    NSLog(@"url1 = %@", url1);
  //    NSLog(@"url2 = %@", url2);

  XCTAssertNotEqualObjects(url1, url2);
}

@end
