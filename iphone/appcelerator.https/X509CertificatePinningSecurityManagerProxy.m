//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "X509CertificatePinningSecurityManagerProxy.h"
#include <libkern/OSAtomic.h>

#import "SecurityManager.h"
#import "PinnedURL.h"
#import "X509Certificate.h"
#import "PublicKey.h"


// Private extensions required by the implementation of
// X509CertificatePinningSecurityManagerProxy.
@interface X509CertificatePinningSecurityManagerProxy ()

// A unique integer that identifies this proxy.
@property (nonatomic, readonly) int32_t proxyId;

// A unique name that identifies this proxy.
@property (nonatomic, strong, readonly) NSString *proxyName;

@property (nonatomic, strong, readonly) SecurityManager *securityManager;

@end


// This counter is used to identify a particular
// X509CertificatePinningSecurityManagerProxy in log statements.
static int32_t proxyCount = 0;


@implementation X509CertificatePinningSecurityManagerProxy

-(id)init {
    self = [super init];
    if (self) {
        _proxyId = OSAtomicIncrement32(&proxyCount);
        _proxyName = [NSString stringWithFormat:@"%@ %d", NSStringFromClass(self.class), _proxyId];
        DebugLog(@"%s, proxyId = %@, proxyName = %@", __PRETTY_FUNCTION__, @(_proxyId), _proxyName);
    }
    
    return self;
}

-(id)_initWithPageContext:(id<TiEvaluator>)context_ args:(NSArray *)args
{
    DebugLog(@"%s %@", __PRETTY_FUNCTION__, args);
    
    // Validate the arguments the Titanium developer passed to the function
    // createX509CertificatePinningSecurityManager (defined in
    // AppceleratorHttpsModule).  An X509CertificatePinningSecurityManager must
    // be constructed with an array of objects containing only the two keys
    // "url" and "serverCertificate". Any deviation from this contract is an
    // error. This protects the Titanium developer from using a SecurityManager
    // incorrectly.
    
    // The argument from the Titanium developer must be an array.
    if (![args isKindOfClass:[NSArray class]] || !(args.count == 1) || ![args[0] isKindOfClass:[NSArray class]]) {
        NSString *reason = @"An X509CertificatePinningSecurityManager must be constructed with an array of objects containing only the two keys 'url' and 'serverCertificate'.";
        NSDictionary *userInfo = @{ @"argument": args };
        NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                         reason:reason
                                                       userInfo:userInfo];
        
        self = nil;
        @throw exception;
    }
    
    NSArray *arrayOfObjects = args[0];
    NSMutableSet *pinnedUrlSet = [NSMutableSet set];
    for (NSDictionary *pinnedURLDict in arrayOfObjects) {
        
        // Each element of the array must be an object.
        if (![pinnedURLDict isKindOfClass:[NSDictionary class]]) {
            NSString *reason = [NSString stringWithFormat:@"Expected an object containing only the two keys 'url' and 'serverCertificate', but received %@.", pinnedURLDict];
            NSDictionary *userInfo = @{ @"object": pinnedURLDict };
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }

        // The object must have a "url" key that is a string.
        NSString *urlString = pinnedURLDict[@"url"];
        if (!(nil != urlString) || ![urlString isKindOfClass:[NSString class]]) {
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
        if (!(nil != serverCertificate) || ![serverCertificate isKindOfClass:[NSString class]]) {
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
        if (!(2 == pinnedURLDict.count)) {
            NSString *reason = [NSString stringWithFormat:@"Unknown key(s) found in object used to construct X509CertificatePinningSecurityManager (only 'url' and 'serverCertificate' are allowed): %@", pinnedURLDict.allKeys];
            NSDictionary *userInfo = @{ @"keys": pinnedURLDict.allKeys };
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }

        NSURL *url = [NSURL URLWithString:urlString];
        if (!(nil != url)) {
            NSString *reason = [NSString stringWithFormat:@"Malformed URL string %@", urlString];
            NSDictionary *userInfo = @{ @"url": urlString };
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }
        
        NSString *baseName       = [serverCertificate stringByDeletingPathExtension];
        NSString *ext            = [serverCertificate pathExtension];
        NSURL    *certificateURL = [[NSBundle mainBundle] URLForResource:baseName withExtension:ext];
        if (!(nil != certificateURL)) {
            NSString *reason = [NSString stringWithFormat:@"Could not find X509 certificate resource with file name %@", serverCertificate];
            NSDictionary *userInfo = @{ @"serverCertificate": serverCertificate };
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }
        
        // The following factory methods are self-validating and will throw
        // NSInvalidArgumentException exceptions. If construction succeeds then
        // the objects are guaranteed to be in a good state.
        X509Certificate *x509Certificate = [X509Certificate x509CertificateWithURL:certificateURL];
        PinnedURL       *pinnedURL       = [PinnedURL pinnedURLWithURL:url andPublicKey:x509Certificate.publicKey];
        [pinnedUrlSet addObject:pinnedURL];
    }
    
    _securityManager = [SecurityManager securityManagerWithPinnedUrlSet:pinnedUrlSet];
    DebugLog(@"%s securityManager = %@", __PRETTY_FUNCTION__, _securityManager);
    
	return [super _initWithPageContext:context_ args:args];
}

#pragma mark SecurityManagerProtocol methods

// Delegate to the SecurityManager.
-(BOOL) willHandleURL:(NSURL*)url {
    DebugLog(@"%s url = %@", __PRETTY_FUNCTION__, url);
    return [self.securityManager willHandleURL:url];
}

// Delegate to the SecurityManager.
-(id<APSConnectionDelegate>) connectionDelegateForUrl:(NSURL*)url {
    DebugLog(@"%s url = %@", __PRETTY_FUNCTION__, url);
    return [self.securityManager connectionDelegateForUrl:url];
}

@end

