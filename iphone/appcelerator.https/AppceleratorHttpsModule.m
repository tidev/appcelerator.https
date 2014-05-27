//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

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
#ifdef DEBUG
    NSLog(@"%s args = %@", __PRETTY_FUNCTION__, args);
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
