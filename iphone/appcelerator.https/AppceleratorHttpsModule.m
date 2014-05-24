/**
 * Appcelerator.Https Module - Authenticate server in HTTPS connections made by
 * TiHTTPClient.
 *
 * Copyright (c) 2014 by Appcelerator, Inc. All Rights Reserved.
 *
 * Licensed under the terms of the Appcelerator Commercial License.
 * Please see the LICENSE included with this distribution for details.
 */

#import "AppceleratorHttpsModule.h"
#import "X509CertificatePinningSecurityManagerProxy.h"

@implementation AppceleratorHttpsModule

-(id)init {
    self = [super init];
    if (self) {
    }
    
    return self;
}

-(id)createX509CertificatePinningSecurityManager:(id)args {
#ifndef NDEBUG
    NSLog(@"[%@] createX509CertificatePinningSecurityManager, args = %@", self.moduleId, args);
#endif
    return [[X509CertificatePinningSecurityManagerProxy alloc] _initWithPageContext:self.pageContext args:args];
}

#pragma mark Internal

-(id)moduleGUID {
    return @"2163621d-1a78-4215-8244-bda08724ffed";
}

-(NSString*)moduleId {
    return @"appcelerator.https";
}

@end
