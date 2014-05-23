//
//  X509CertificatePinningSecurityManager.m
//  appcelerator.https
//
//  Created by Matt Langston on 5/22/14.
//  Copyright (c) 2014 Appcelerator. All rights reserved.
//

#import "X509CertificatePinningSecurityManagerProxy.h"
#include <libkern/OSAtomic.h>
#import "PinnedURL.h"
#import "SecurityManager.h"


// Private extensions required by the implementation of
// X509CertificatePinningSecurityManagerProxy.
@interface X509CertificatePinningSecurityManagerProxy ()

// A unique integer that identifies this proxy.
@property (nonatomic,readonly) int32_t proxyId;

// A unique name that identifies this proxy.
@property (nonatomic,readonly) NSString *proxyName;

@end


// This counter is used to identify a particular
// X509CertificatePinningSecurityManagerProxy in log statements.
static int32_t proxyCount = 0;


@implementation X509CertificatePinningSecurityManagerProxy

-(id)init {
    self = [super init];
    if (self) {
        _proxyId = OSAtomicIncrement32(&proxyCount);
        _proxyName = [NSString stringWithFormat:@"X509CertificatePinningSecurityManagerProxy %d", _proxyId];
        NSLog(@"[%@] init", _proxyName);
    }
    
    return self;
}

-(id)_initWithPageContext:(id<TiEvaluator>)context_ args:(NSArray *)args
{
    NSLog(@"[%@] _initWithPageContext: properties = %@", self.proxyName, args);
    
    // Validate the arguments the Titanium developer passed to the function
    // createX509CertificatePinningSecurityManager (defined in
    // AppceleratorHttpsModule).  An X509CertificatePinningSecurityManager must
    // be constructed with an array of objects containing only the two keys
    // "url" and "serverCertificate". Any deviation from this contract is an
    // error. This protects the Titanium developer from using a SecurityManager
    // incorrectly.
    
    // The argument from the Titanium developer must be an array.
    if (![args isKindOfClass:[NSArray class]]) {
        NSString *reason = @"An X509CertificatePinningSecurityManager must be constructed with an array of objects containing only the two keys \"url\" and \"serverCertificate\".";
        NSDictionary *userInfo = @{ @"argument": args };
        NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                         reason:reason
                                                       userInfo:userInfo];
        
        self = nil;
        @throw exception;
    }

    for (NSDictionary *pinnedURLDict in args) {
        
        // Each element of the array must be an object.
        if (![pinnedURLDict isKindOfClass:[NSDictionary class]]) {
            NSString *reason = [NSString stringWithFormat:@"Expected an object containing only the two keys \"url\" and \"serverCertificate\", but received %@.", pinnedURLDict];
            NSDictionary *userInfo = @{ @"object": pinnedURLDict };
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }

        // The object must have a "url" key that is a string.
        NSString *urlString = pinnedURLDict[@"url"];
        if (urlString == nil || ![urlString isKindOfClass:[NSString class]]) {
            NSString *reason = @"Missing url property for X509CertificatePinningSecurityManager";
            NSDictionary *userInfo = nil;
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }
        
        
        // The object must have a "serverCertificate" key that is a string.
        NSString *serverCertificate = pinnedURLDict[@"serverCertificate"];
        if (serverCertificate == nil || ![serverCertificate isKindOfClass:[NSString class]]) {
            NSString *reason = @"Missing serverCertificate property for X509CertificatePinningSecurityManager";
            NSDictionary *userInfo = nil;
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }
        
        // It is an error if there are additional entries in the object,
        // which is an indication that the Titanium developer is creating a
        // SecurityManager incorrectly.
        if (pinnedURLDict.count > 2) {
            NSString *reason = [NSString stringWithFormat:@"Unknown key(s) found in object used to construct X509CertificatePinningSecurityManager (only \"url\" and \"serverCertificate\" are allowed): %@", pinnedURLDict.allKeys];
            NSDictionary *userInfo = @{ @"keys": pinnedURLDict.allKeys };
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }
    }
    
	return [super _initWithPageContext:context_ args:args];
}

@end
