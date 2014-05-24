//
//  AbstractBaseTest.h
//  CertificatePinningSecurityManager
//
//  Created by Matt Langston on 5/19/14.
//  Copyright (c) 2014 Appcelerator. All rights reserved.
//

#import <XCTest/XCTest.h>

@interface AbstractBaseTest : XCTestCase

// This dictionary is a map of file base names (the keys) to NSURLs (the values)
// for DER encoded X509 certificates embedded in the app's Resources directory.
@property (nonatomic, strong, readonly) NSDictionary *certificateURLDict;

@end
