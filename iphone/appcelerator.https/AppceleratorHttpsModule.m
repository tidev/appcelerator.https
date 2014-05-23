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
//#import "TiBase.h"
//#import "TiHost.h"
//#import "TiUtils.h"

@interface AppceleratorHttpsModule ()
@end


@implementation AppceleratorHttpsModule

-(id)init {
    self = [super init];
    if (self) {
    }
    
    return self;
}

-(id)createX509CertificatePinningSecurityManager:(id)args {
    NSLog(@"[%@] createX509CertificatePinningSecurityManager, args = %@", self.moduleId, args);
    X509CertificatePinningSecurityManagerProxy *proxy = [[X509CertificatePinningSecurityManagerProxy alloc] _initWithPageContext:self.pageContext args:args];
    return proxy;
}

#pragma mark Lifecycle

-(void)startup {
    [super startup];
    NSLog(@"[%@] startup", self.moduleId);
}

-(void)shutdown:(id)sender {
    NSLog(@"[%@] shutdown", self.moduleId);
    [super shutdown:sender];
}

#pragma mark Internal

-(id)moduleGUID {
    return @"2163621d-1a78-4215-8244-bda08724ffed";
}

-(NSString*)moduleId {
    return @"appcelerator.https";
}

@end
