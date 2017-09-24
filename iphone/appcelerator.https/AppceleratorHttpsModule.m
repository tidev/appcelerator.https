//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "AppceleratorHttpsModule.h"
#import "X509CertificatePinningSecurityManagerProxy.h"

@implementation AppceleratorHttpsModule

static BOOL _requiredCertPinng = NO;

-(id)init {
    self = [super init];
    if (self) {
    }
    
    return self;
}

// The requiredCertPinng method provides a static way other
// classes can access this property. Given on whe proxy is arranged
// this seemed the best way to access without changing the interface
+ (BOOL)requiredCertPinng {
    return _requiredCertPinng;
}

// The requireCertificatePinning methid is used to set the
// option on how fall through urls are handled.
// if set to false when a url is not found it will continue to execute
// if set to true, the module will block execution
-(void)requireCertificatePinning:(NSNumber *)value {
    _requiredCertPinng = [TiUtils boolValue:value];
}

-(id)createX509CertificatePinningSecurityManager:(id)args {
    DebugLog(@"%s args = %@", __PRETTY_FUNCTION__, args);
    id context = ([self executionContext]==nil)?[self pageContext]:[self executionContext];
    return [[X509CertificatePinningSecurityManagerProxy alloc] _initWithPageContext:context args:args];
}

#pragma mark Internal

-(id)moduleGUID {
    return @"2163621d-1a78-4215-8244-bda08724ffed";
}

-(NSString*)moduleId {
    return @"appcelerator.https";
}

@end
