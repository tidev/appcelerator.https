//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "SecurityManager.h"
#import "PinnedURL.h"
#import "AppceleratorHttpsUtils.h"
#import "AppceleratorHttps.h"

// Private extensions required by the implementation of SecurityManager.
@interface SecurityManager ()

// This property exists as an optimiation to provide O(1) lookup time of the
// public key for a specific host. The keys are the host element of the URL and
// the values are instances of PublicKey.
@property (nonatomic, strong, readonly) NSDictionary *dnsNameToPublicKeyMap;

@end

@implementation SecurityManager

+(instancetype)securityManagerWithPinnedUrlSet:(NSSet *)pinnedUrlSet {
#ifdef DEBUG
    NSLog(@"%s", __PRETTY_FUNCTION__);
#endif
    return [[SecurityManager alloc] initWithPinnedURLs:pinnedUrlSet];
}

// Designated initializer.
-(instancetype)initWithPinnedURLs:(NSSet *)pinnedUrlSet {
#ifdef DEBUG
    NSLog(@"%s pinnedUrlSet = %@", __PRETTY_FUNCTION__, pinnedUrlSet);
#endif
    
    self = [super init];
    if (self) {
        if (!(nil != pinnedUrlSet)) {
            NSString *reason = @"pinnedUrlSet must not be nil";
            NSDictionary *userInfo = nil;
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }

        if (!(pinnedUrlSet.count > 0)) {
            NSString *reason = @"pinnedUrlSet must have at least one PinnedURL object.";
            NSDictionary *userInfo = @{ @"pinnedUrlSet": pinnedUrlSet };
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }

        // Make a copy of the set. This is basic secure coding practice.
        _pinnedUrlSet = [pinnedUrlSet copy];
        
        // Create a temporary mutable dictionary that maps the host element of
        // the URL (they keys) to the PublicKey instances (the values) for the
        // given set of PinnedURL instances.
        NSMutableDictionary *dnsNameToPublicKeyMap = [NSMutableDictionary dictionaryWithCapacity:_pinnedUrlSet.count];
        for(PinnedURL* pinnedURL in _pinnedUrlSet) {
            // It is an error to pin the same URL more than once.
            if (dnsNameToPublicKeyMap[pinnedURL.host] != nil) {
                NSString *reason = [NSString stringWithFormat:@"A host name can only be pinned to one public key: %@", pinnedURL.host];
                NSDictionary *userInfo = @{ @"url" : pinnedURL.url };
                NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                                 reason:reason
                                                               userInfo:userInfo];
                
                self = nil;
                @throw exception;
            }

            // Normalize the host to lower case.
            NSString *host = [pinnedURL.host lowercaseString];
            dnsNameToPublicKeyMap[host] = pinnedURL.publicKey;
        }
        
        // Make an immutable copy of the dictionary.
        _dnsNameToPublicKeyMap = [NSDictionary dictionaryWithDictionary:dnsNameToPublicKeyMap];
    }
    
    return self;
}

- (BOOL)isEqualToSecurityManager:(SecurityManager *)rhs {
    if (!rhs) {
        return NO;
    }
    
    BOOL equal = [self.pinnedUrlSet isEqualToSet:rhs.pinnedUrlSet];
    return equal;
}

#pragma mark SecurityManagerProtocol methods

// Return FALSE unless this security manager was specifically configured to
// handle this URL.
-(BOOL) willHandleURL:(NSURL*)url {
#ifdef DEBUG
    NSLog(@"%s url = %@", __PRETTY_FUNCTION__, url);
#endif
    if (url == nil) {
        return FALSE;
    }

    // The scheme must be https. Note the use of
    // localizedCaseInsensitiveCompare, which is a secure coding practice
    // since URL components are case-insensitive as described in RFCs 1808,
    // 1738, and 2732.
    if ([url.scheme localizedCaseInsensitiveCompare:@"https"] != NSOrderedSame) {
        NSLog(@"[WARN] Do not handle URL scheme %@ (the scheme must be https for us to handle it)", url.scheme);
        return FALSE;
    }
    
    // Normalize the host to lower case.
    NSString *host = [url.host lowercaseString];
    BOOL containsHostName = (self.dnsNameToPublicKeyMap[host] != nil);

#ifdef DEBUG
    NSLog(@"%s returns %@ for url = %@", __PRETTY_FUNCTION__, NSStringFromBOOL(containsHostName), url);
#endif

    return containsHostName;
}

// If this security manager was configured to handle this url then return self.
-(id<APSConnectionDelegate>) connectionDelegateForUrl:(NSURL*)url {
#ifdef DEBUG
    NSLog(@"%s url = %@", __PRETTY_FUNCTION__, url);
#endif
    if ([self willHandleURL:url]) {
        return self;
    } else {
        return nil;
    }
}

#pragma mark APSConnectionDelegate methods

// Return FALSE unless the NSURLAuthenticationChallenge is for TLS trust
// validation (aka NSURLAuthenticationMethodServerTrust) and this security
// manager was configured to handle the current url.
-(BOOL)willHandleChallenge:(NSURLAuthenticationChallenge *)challenge forConnection:(NSURLConnection *)connection {
#ifdef DEBUG
    NSLog(@"%s challenge = %@, connection = %@", __PRETTY_FUNCTION__, challenge, connection);
#endif
    BOOL result = FALSE;
    if ([challenge.protectionSpace.authenticationMethod isEqualToString: NSURLAuthenticationMethodServerTrust])
    {
        NSURL *currentURL = connection.currentRequest.URL;
        result = [self willHandleURL:currentURL];
    }
    
#ifdef DEBUG
    NSLog(@"%s returns %@, challenge = %@, connection = %@", __PRETTY_FUNCTION__, NSStringFromBOOL(result), challenge, connection);
#endif
    return result;
}

#pragma mark NSURLConnectionDelegate methods

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
#ifdef DEBUG
    NSLog(@"%s connection = %@, challenge = %@", __PRETTY_FUNCTION__, connection, challenge);
#endif
    if ([challenge.protectionSpace.authenticationMethod isEqualToString: NSURLAuthenticationMethodServerTrust])
    {
        // It is a logic error (i.e. a bug in Titanium) if this method is
        // called with a URL the security manager was not configured to
        // handle.
        if (![self willHandleURL:connection.currentRequest.URL]) {
            NSString *reason = [NSString stringWithFormat:@"LOGIC ERROR: Titanium bug called this SecurityManager with an unknown host \"%@\". Please report this issue to us at https://jira.appcelerator.org/browse/TIMOB", connection.currentRequest.URL.host];
            NSDictionary *userInfo = @{ @"connection" : connection };
            NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            @throw exception;
        }

        do
        {
            SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
            if(!(nil != serverTrust)) {
#ifdef DEBUG
                NSLog(@"%s FAIL: challenge.protectionSpace.serverTrust is nil", __PRETTY_FUNCTION__);
#endif
                break; /* failed */
            }
            
            // SecTrustEvaluate performs customary X509
            // checks. Unusual conditions will cause the function to
            // return *non-success*. Unusual conditions include an
            // expired certifcate or self signed certifcate.
            OSStatus status = SecTrustEvaluate(serverTrust, NULL);
            if(!(errSecSuccess == status)) {
#ifdef DEBUG
                NSLog(@"%s FAIL: standard TLS validation failed. SecTrustEvaluate returned %@", __PRETTY_FUNCTION__, @(status));
#endif
                break; /* failed */
            }

#ifdef DEBUG
            NSLog(@"%s SecTrustEvaluate returned %@", __PRETTY_FUNCTION__, @(status));
#endif

            // Normalize the server's host name to lower case.
            NSString *host = [connection.currentRequest.URL.host lowercaseString];
            
#ifdef DEBUG
            NSLog(@"%s Normalized host name = %@", __PRETTY_FUNCTION__, host);
#endif

            // Get the PinnedURL for this server.
            PublicKey *pinnedPublicKey = self.dnsNameToPublicKeyMap[host];

            // It is a logic error (a bug in this SecurityManager class) if this
            // security manager does not have a PinnedURL for this server.
            if (!(nil != pinnedPublicKey)) {
                NSString *reason = [NSString stringWithFormat:@"LOGIC ERROR: appcelerator.https module bug: SecurityManager could not find a PublicKey for host \"%@\". Please report this issue to us at https://jira.appcelerator.org/browse/MOD-1706", connection.currentRequest.URL.host];
                NSDictionary *userInfo = @{ @"connection" : connection };
                NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                                 reason:reason
                                                               userInfo:userInfo];
                
                @throw exception;
            }
            
#ifdef DEBUG
            NSLog(@"%s host %@ pinned to publicKey %@", __PRETTY_FUNCTION__, host, pinnedPublicKey);
#endif

            // Obtain the server's X509 certificate and public key.
            SecCertificateRef serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
            if(!(nil != serverCertificate)) {
#ifdef DEBUG
                NSLog(@"%s FAIL: Could not find the server's X509 certificate in serverTrust", __PRETTY_FUNCTION__);
#endif
                break;  /* failed */
            }
            
            // Create a friendlier Objective-C wrapper around this server's X509
            // certificate.
            X509Certificate *x509Certificate = [X509Certificate x509CertificateWithSecCertificate:serverCertificate];
            if (!(nil != x509Certificate)) {
                // CFBridgingRelease transfer's ownership of the CFStringRef
                // returned by CFCopyDescription to ARC.
                NSString *serverCertificateDescription = (NSString *)CFBridgingRelease(CFCopyDescription(serverCertificate));
                NSString *reason = [NSString stringWithFormat:@"LOGIC ERROR: appcelerator.https module bug: SecurityManager could not create an X509Certificate for host \"%@\" using the SecCertificateRef \"%@\". Please report this issue to us at https://jira.appcelerator.org/browse/MOD-1706", connection.currentRequest.URL.host, serverCertificateDescription];
                NSDictionary *userInfo = @{ @"x509Certificate" : x509Certificate };
                NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                                 reason:reason
                                                               userInfo:userInfo];
                
                @throw exception;
            }
            
#ifdef DEBUG
            NSLog(@"%s server's X509 certificate = %@", __PRETTY_FUNCTION__, x509Certificate);
#endif
            // Get the public key from this server's X509 certificate.
            PublicKey *serverPublicKey = x509Certificate.publicKey;
            if (!(nil != serverPublicKey)) {
                NSString *reason = [NSString stringWithFormat:@"LOGIC ERROR: appcelerator.https module bug: SecurityManager could not find the server's public key for host \"%@\" in the X509 certificate \"%@\". Please report this issue to us at https://jira.appcelerator.org/browse/MOD-1706", connection.currentRequest.URL.host, x509Certificate];
                NSDictionary *userInfo = @{ @"x509Certificate" : x509Certificate };
                NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                                 reason:reason
                                                               userInfo:userInfo];
                
                @throw exception;
            }
            
#ifdef DEBUG
            NSLog(@"%s server's public key = %@", __PRETTY_FUNCTION__, serverPublicKey);
#endif

            // Compare the public keys. If they match, then the server is
            // authenticated.
            BOOL publicKeysAreEqual = [pinnedPublicKey isEqualToPublicKey:serverPublicKey];
            if(!(YES == publicKeysAreEqual)) {
                NSLog(@"[WARN] Potential \"Man-in-the-Middle\" attack detected since host %@ does not hold the private key corresponding to the public key %@.", host, pinnedPublicKey);
                break; /* failed */
            }
            
#ifdef DEBUG
            NSLog(@"%s publicKeysAreEqual = %@", __PRETTY_FUNCTION__, NSStringFromBOOL(publicKeysAreEqual));
#endif
            // Return success since the server holds the private key
            // corresponding to the public key held bu this security manager.
            return [challenge.sender useCredential:[NSURLCredential credentialForTrust:serverTrust] forAuthenticationChallenge:challenge];
            
        } while (0);
    }
    
    // Return fail.
    return [challenge.sender cancelAuthenticationChallenge:challenge];
}

#pragma mark - NSObject

- (BOOL)isEqual:(id)rhs {
    if (self == rhs) {
        return YES;
    }
    
    if (![rhs isKindOfClass:[SecurityManager class]]) {
        return NO;
    }
    
    return [self isEqualToSecurityManager:(SecurityManager *)rhs];
}

- (NSUInteger)hash {
    return self.pinnedUrlSet.hash;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@: %@", NSStringFromClass(self.class), self.pinnedUrlSet];
}

@end
