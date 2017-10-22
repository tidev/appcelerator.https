//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "X509CertificatePinningSecurityManagerProxy.h"

#import "SecurityManager.h"
#import "PinnedURL.h"
#import "X509Certificate.h"
#import "PublicKey.h"
#import "TiUtils.h"

// Private extensions required by the implementation of
// X509CertificatePinningSecurityManagerProxy.
@interface X509CertificatePinningSecurityManagerProxy ()

@property (nonatomic, strong, readonly) SecurityManager *securityManager;

@end


// This counter is used to identify a particular
// X509CertificatePinningSecurityManagerProxy in log statements.
static int32_t proxyCount = 0;
static dispatch_queue_t syncQueue;



@implementation X509CertificatePinningSecurityManagerProxy

+ (void) initialize{
    syncQueue = dispatch_queue_create("appcelerator.https.syncQueue", NULL);
}

-(id)init {
    self = [super init];
    if (self) {
        
        dispatch_sync(syncQueue, ^{
            ++proxyCount;
            NSString *proxyName = [NSString stringWithFormat:@"%@ %d", NSStringFromClass(self.class), proxyCount];
            DebugLog(@"proxyId = %@, proxyName = %@", @(proxyCount), proxyName);
        });
    }
    
    return self;
}

-(id)_initWithPageContext:(id<TiEvaluator>)context_ args:(NSArray *)args
{
    DebugLog(@"%s %@", __PRETTY_FUNCTION__, args);
    
    if (self = [super _initWithPageContext:context_]) {
        
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
            
            NSURL *certificateURL = [TiUtils toURL:serverCertificate proxy:self];
            if (!(nil != certificateURL)) {
                NSString *reason = [NSString stringWithFormat:@"Could not find X509 certificate resource with file name %@", serverCertificate];
                NSDictionary *userInfo = @{ @"serverCertificate": serverCertificate };
                NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                                 reason:reason
                                                               userInfo:userInfo];
                
                self = nil;
                @throw exception;
            }
            
            NSInteger certificateIndex = [TiUtils intValue:pinnedURLDict[@"trustChainIndex"] def:0];
            if (certificateIndex < 0) {
                NSString *reason = [NSString stringWithFormat:@"Cannot use negative trust-chain certificate-index %li", (long)certificateIndex];
                NSDictionary *userInfo = @{ @"certificateIndex": NUMINTEGER(certificateIndex) };
                NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                                 reason:reason
                                                               userInfo:userInfo];
                
                self = nil;
                @throw exception;
            }
            
            // The following factory methods are self-validating and will throw
            // NSInvalidArgumentException exceptions. If construction succeeds then
            // the objects are guaranteed to be in a good state.
            X509Certificate *x509Certificate = [X509Certificate x509CertificateWithURL:certificateURL andTrustChainIndex:certificateIndex];
            PinnedURL       *pinnedURL       = [PinnedURL pinnedURLWithURL:url andPublicKey:x509Certificate.publicKey];
            [pinnedUrlSet addObject:pinnedURL];
        }
        
        _securityManager = [SecurityManager securityManagerWithPinnedUrlSet:pinnedUrlSet];
        DebugLog(@"%s securityManager = %@", __PRETTY_FUNCTION__, _securityManager);
    }
    return self;
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

