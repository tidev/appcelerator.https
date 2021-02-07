//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "SecurityManager.h"
#import "AppceleratorHttps.h"
#import "PinnedURL.h"

// Private extensions required by the implementation of SecurityManager.
@interface SecurityManager ()

// This property exists as an optimiation to provide O(1) lookup time of the
// public key for a specific host. The keys are the host element of the URL and
// the values are instances of PublicKey.
@property (nonatomic, strong, readonly) NSDictionary<NSString *, NSMutableSet<PublicKey *> *>  *dnsNameToPublicKeyMap;

// Try the same for client-certificates
@property (nonatomic, strong, readonly) NSDictionary<NSString *, ClientCertificate *> *dnsNameToClientCertificateMap;

@end

@implementation SecurityManager

+ (instancetype)securityManagerWithPinnedUrlSet:(NSSet *)pinnedUrlSet
{
  DebugLog(@"%s", __PRETTY_FUNCTION__);
  return [[SecurityManager alloc] initWithPinnedURLs:pinnedUrlSet];
}

// Designated initializer.
- (instancetype)initWithPinnedURLs:(NSSet *)pinnedUrlSet
{
  DebugLog(@"%s pinnedUrlSet = %@", __PRETTY_FUNCTION__, pinnedUrlSet);

  self = [super init];
  if (self) {
    if (pinnedUrlSet == nil) {
      NSString *reason = @"pinnedUrlSet must not be nil";
      NSDictionary *userInfo = nil;
      NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                       reason:reason
                                                     userInfo:userInfo];

      self = nil;
      @throw exception;
    }

    if (pinnedUrlSet.count == 0) {
      NSString *reason = @"pinnedUrlSet must have at least one PinnedURL object.";
      NSDictionary *userInfo = @{ @"pinnedUrlSet" : pinnedUrlSet };
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
    NSMutableDictionary *dnsNameToClientCertificateMap = [NSMutableDictionary dictionaryWithCapacity:_pinnedUrlSet.count];

    for (PinnedURL *pinnedURL in _pinnedUrlSet) {
      // Normalize the host to lower case.
      NSString *host = [pinnedURL.host lowercaseString];
      if (dnsNameToPublicKeyMap[host] == nil) {
          dnsNameToPublicKeyMap[pinnedURL.host] = [[NSMutableSet alloc] init];
      }

      [dnsNameToPublicKeyMap[host]  addObject: pinnedURL.publicKey];

      if (pinnedURL.clientCertificate != nil) {
        dnsNameToClientCertificateMap[host] = pinnedURL.clientCertificate;
      }
    }

    // Make an immutable copy of the dictionary.
    _dnsNameToPublicKeyMap = [NSDictionary dictionaryWithDictionary:dnsNameToPublicKeyMap];
    _dnsNameToClientCertificateMap = [NSDictionary dictionaryWithDictionary:dnsNameToClientCertificateMap];
  }

  return self;
}

- (BOOL)isEqualToSecurityManager:(SecurityManager *)rhs
{
  if (!rhs) {
    return NO;
  }

  BOOL equal = [self.pinnedUrlSet isEqualToSet:rhs.pinnedUrlSet];
  return equal;
}

#pragma mark SecurityManagerProtocol methods

// Return NO unless this security manager was specifically configured to
// handle this URL.
- (BOOL)willHandleURL:(NSURL *)url
{
  DebugLog(@"%s url = %@", __PRETTY_FUNCTION__, url);
  if (url == nil) {
    return NO;
  }

  // Normalize the host to lower case.
  NSString *host = [url.host lowercaseString];
  BOOL containsHostName = [self publicKeyForHost:host] != nil;

  DebugLog(@"%s returns %@ for url = %@ host = %@", __PRETTY_FUNCTION__, containsHostName ? @"YES" : @"NO", url, host);

  return containsHostName;
}

/**
 Returns the public key for a given host

 This first performs a quick lookup by comparing hostnames. If none matched
 we check if any wildcard entries are defined and do a regex compare against those.

 @param host Host to get the public key for

 @return The public key if found or nil
 */
- (NSMutableSet<PublicKey *> *)publicKeyForHost:(NSString *)host {
    NSMutableSet<PublicKey *> *directMatches = self.dnsNameToPublicKeyMap[host];
    if (directMatches != nil) {
        return directMatches;
    }

  NSError *error = nil;
  for (NSString *hostKey in self.dnsNameToPublicKeyMap.allKeys) {
    if ([hostKey rangeOfString:@"*."].length == 0) {
      continue;
    }

    NSString *wildcardRegexPattern = [NSRegularExpression escapedPatternForString:hostKey];
    wildcardRegexPattern = [wildcardRegexPattern stringByReplacingOccurrencesOfString:@"\\*\\." withString:@"([a-z0-9\\-]+\\.)*"];
    NSRegularExpression *wildcardRegex = [NSRegularExpression regularExpressionWithPattern:wildcardRegexPattern options:NSRegularExpressionCaseInsensitive error:&error];
    if (error != nil) {
      NSLog(@"[ERROR] Could not initialize RegEx with pattern %@ to match possible wildcard certificates.", wildcardRegexPattern);
      NSLog(@"[ERROR] The error was: %@", error.localizedDescription);
      continue;
    }
    NSInteger numberOfMatches = [wildcardRegex numberOfMatchesInString:host options:0 range:NSMakeRange(0, host.length)];
    if (numberOfMatches > 0) {
      return self.dnsNameToPublicKeyMap[hostKey];
    }
  }

  return nil;
}

/**
 Returns the client certificate for a given host
 
 This first performs a quick lookup by comparing hostnames. If none matched
 we check if any wildcard entries are defined and do a regex compare against those.
 
 @param host Host to get the client-certificate for
 
 @return The client-certificate if found or nil
 */
- (ClientCertificate *)clientCertificateForHost:(NSString *)host
{
  ClientCertificate *directMatch = self.dnsNameToClientCertificateMap[host];
  if (directMatch != nil) {
    return directMatch;
  }

  NSError *error = nil;
  for (NSString *hostKey in self.dnsNameToClientCertificateMap.allKeys) {
    if ([hostKey rangeOfString:@"*."].length == 0) {
      continue;
    }

    NSString *wildcardRegexPattern = [NSRegularExpression escapedPatternForString:hostKey];
    wildcardRegexPattern = [wildcardRegexPattern stringByReplacingOccurrencesOfString:@"\\*\\." withString:@"([a-z0-9\\-]+\\.)*"];
    NSRegularExpression *wildcardRegex = [NSRegularExpression regularExpressionWithPattern:wildcardRegexPattern options:NSRegularExpressionCaseInsensitive error:&error];
    if (error != nil) {
      NSLog(@"[ERROR] Could not initialize RegEx with pattern %@ to match possible wildcard certificates.", wildcardRegexPattern);
      NSLog(@"[ERROR] The error was: %@", error.localizedDescription);
      continue;
    }
    NSInteger numberOfMatches = [wildcardRegex numberOfMatchesInString:host options:0 range:NSMakeRange(0, host.length)];
    if (numberOfMatches > 0) {
      return self.dnsNameToClientCertificateMap[hostKey];
    }
  }

  return nil;
}

// If this security manager was configured to handle this url then return self.
- (id<APSConnectionDelegate>)connectionDelegateForUrl:(NSURL *)url
{
  DebugLog(@"%s url = %@", __PRETTY_FUNCTION__, url);
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
- (BOOL)willHandleChallenge:(NSURLAuthenticationChallenge *)challenge forSession:(NSURLSession *)session
{
  BOOL result = NO;
  if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] ||
      [challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate]) {
    NSURL *currentURL = [NSURL URLWithString:challenge.protectionSpace.host];
    if (currentURL.scheme == nil) {
      currentURL = [NSURL URLWithString:[NSString stringWithFormat:@"https://%@", challenge.protectionSpace.host]];
    }
    result = [self willHandleURL:currentURL];
  }

  DebugLog(@"%s returns %@, challenge = %@, session = %@ URL = %@", __PRETTY_FUNCTION__, result ? @"YES" : @"NO", challenge, session, challenge.protectionSpace.host);
  return result;
}

- (BOOL)willHandleChallenge:(NSURLAuthenticationChallenge *)challenge forConnection:(NSURLConnection *)connection
{
  BOOL result = NO;
  if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] ||
      [challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate]) {
    NSURL *currentURL = [NSURL URLWithString:challenge.protectionSpace.host];
    if (currentURL.scheme == nil) {
      currentURL = [NSURL URLWithString:[NSString stringWithFormat:@"https://%@", challenge.protectionSpace.host]];
    }
    result = [self willHandleURL:currentURL];
  }

  DebugLog(@"%s returns %@, challenge = %@, connection = %@ URL = %@", __PRETTY_FUNCTION__, result ? @"YES" : @"NO", challenge, connection, challenge.protectionSpace.host);
  return result;
}

#pragma mark NSURLConnectionDelegate methods

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *_Nullable))completionHandler
{
  DebugLog(@"%s session = %@, challenge = %@", __PRETTY_FUNCTION__, session, challenge);
  // Normalize the server's host name to lower case.
  NSString *host = [task.currentRequest.URL.host lowercaseString];
  DebugLog(@"%s Normalized host name = %@", __PRETTY_FUNCTION__, host);

  // Get the PinnedURL for this server.
  ClientCertificate *pinnedClientCertificate = [self clientCertificateForHost:host];
  NSString *authenticationMethod = [[challenge protectionSpace] authenticationMethod];

  // Handle Two-phase mutual client-authentification
  if ([authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate] && pinnedClientCertificate != nil) {
    NSData *p12Data = [NSData dataWithContentsOfURL:pinnedClientCertificate.url];

    if (!p12Data) {
      NSString *reason = [NSString stringWithFormat:@"Certificate data could not be extracted for host = %@.", task.currentRequest.URL.host];
      NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                       reason:reason
                                                     userInfo:nil];
      @throw exception;
    }

    CFDataRef inPKCS12Data = (__bridge CFDataRef)p12Data;
    SecIdentityRef identity;
    OSStatus result = [self extractIdentity:&identity from:inPKCS12Data with:pinnedClientCertificate.password];

    if (result != noErr) {
      [challenge.sender cancelAuthenticationChallenge:challenge];
      completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
      return;
    }

    SecCertificateRef certificate = NULL;
    SecIdentityCopyCertificate(identity, &certificate);
    const void *certificates[] = { certificate };
    CFArrayRef certificatesArray = CFArrayCreate(kCFAllocatorDefault, certificates, 1, NULL);

    // create a credential from the certificate and ideneity, then reply to the challenge with the credential
    NSURLCredential *credential = [NSURLCredential credentialWithIdentity:identity
                                                             certificates:(__bridge NSArray *)certificatesArray
                                                              persistence:NSURLCredentialPersistencePermanent];
    [challenge.sender useCredential:credential forAuthenticationChallenge:challenge];
    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    return;
  }

  if (![authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
    [challenge.sender cancelAuthenticationChallenge:challenge];
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    return;
  }

  // It is a logic error (i.e. a bug in Titanium) if this method is
  // called with a URL the security manager was not configured to
  // handle.
  if (![self willHandleURL:task.currentRequest.URL]) {
    NSString *reason = [NSString stringWithFormat:@"LOGIC ERROR: Titanium bug called this SecurityManager with an unknown host \"%@\". Please report this issue to us at https://jira.appcelerator.org/browse/TIMOB", task.currentRequest.URL.host];
    NSDictionary *userInfo = @{ @"session" : session };
    NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                     reason:reason
                                                   userInfo:userInfo];
    @throw exception;
  }

  SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
  if (serverTrust == nil) {
    DebugLog(@"%s FAIL: challenge.protectionSpace.serverTrust is nil", __PRETTY_FUNCTION__);
    [challenge.sender cancelAuthenticationChallenge:challenge];
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    return;
  }

  // SecTrustEvaluate performs customary X509
  // checks. Unusual conditions will cause the function to
  // return *non-success*. Unusual conditions include an
  // expired certifcate or self signed certifcate.
  OSStatus status = SecTrustEvaluate(serverTrust, NULL);
  if (status != errSecSuccess) {
    DebugLog(@"%s FAIL: standard TLS validation failed. SecTrustEvaluate returned %@", __PRETTY_FUNCTION__, @(status));
    [challenge.sender cancelAuthenticationChallenge:challenge];
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    return;
  }
  DebugLog(@"%s SecTrustEvaluate returned %@", __PRETTY_FUNCTION__, @(status));

  // Get the PinnedURL for this server.
  NSMutableSet<PublicKey *> *pinnedPublicKeys = [self publicKeyForHost:host];

  // It is a logic error (a bug in this SecurityManager class) if this
  // security manager does not have a PinnedURL for this server.
  if (pinnedPublicKeys == nil) {
    NSString *reason = [NSString stringWithFormat:@"LOGIC ERROR: appcelerator.https module bug: SecurityManager could not find a PublicKey for host \"%@\". Please report this issue to us at https://jira.appcelerator.org/browse/MOD-1706", task.currentRequest.URL.host];
    NSDictionary *userInfo = @{ @"session" : session };
    NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                     reason:reason
                                                   userInfo:userInfo];
    @throw exception;
  }
  DebugLog(@"%s host %@ pinned to publicKey %@", __PRETTY_FUNCTION__, host, pinnedPublicKeys);

  CFIndex count = SecTrustGetCertificateCount(serverTrust);
  CFIndex i = 0;
  DebugLog(@"Number of certificates: %ld", count);

  for (i = 0; i < count; i++) {
    SecCertificateRef item = SecTrustGetCertificateAtIndex(serverTrust, i);
    NSString *desc = (NSString *)CFBridgingRelease(CFCopyDescription(item));
    DebugLog(@"%ld: %@", i, desc);
  }

  // Obtain the server's X509 certificate and public key.
  SecCertificateRef serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, pinnedPublicKey.anyObject.trustChainIndex);
  if (serverCertificate == nil) {
    DebugLog(@"%s FAIL: Could not find the server's X509 certificate in serverTrust", __PRETTY_FUNCTION__);
    [challenge.sender cancelAuthenticationChallenge:challenge];
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    return;
  }

  // Create a friendlier Objective-C wrapper around this server's X509
  // certificate.
  X509Certificate *x509Certificate = [X509Certificate x509CertificateWithSecCertificate:serverCertificate andTrustChainIndex:pinnedPublicKey.trustChainIndex];
  if (x509Certificate == nil) {
    // CFBridgingRelease transfer's ownership of the CFStringRef
    // returned by CFCopyDescription to ARC.
    NSString *serverCertificateDescription = (NSString *)CFBridgingRelease(CFCopyDescription(serverCertificate));
    NSString *reason = [NSString stringWithFormat:@"LOGIC ERROR: appcelerator.https module bug: SecurityManager could not create an X509Certificate for host \"%@\" using the SecCertificateRef \"%@\". Please report this issue to us at https://jira.appcelerator.org/browse/MOD-1706", task.currentRequest.URL.host, serverCertificateDescription];
    NSDictionary *userInfo = @{ @"x509Certificate" : [NSNull null] };
    NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                     reason:reason
                                                   userInfo:userInfo];
    @throw exception;
  }

  DebugLog(@"%s server's X509 certificate = %@", __PRETTY_FUNCTION__, x509Certificate);
  // Get the public key from this server's X509 certificate.
  PublicKey *serverPublicKey = x509Certificate.publicKey;
  if (serverPublicKey == nil) {
    NSString *reason = [NSString stringWithFormat:@"LOGIC ERROR: appcelerator.https module bug: SecurityManager could not find the server's public key for host \"%@\" in the X509 certificate \"%@\". Please report this issue to us at https://jira.appcelerator.org/browse/MOD-1706", task.currentRequest.URL.host, x509Certificate];
    NSDictionary *userInfo = @{ @"x509Certificate" : x509Certificate };
    NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                     reason:reason
                                                   userInfo:userInfo];
    @throw exception;
  }

  DebugLog(@"%s server's public key = %@", __PRETTY_FUNCTION__, serverPublicKey);

  // Compare the public keys. If they match, then the server is
  // authenticated.
  BOOL publicKeysAreEqual = NO;
  for (PublicKey *pinnedPublicKey in pinnedPublicKeys) {
   publicKeysAreEqual = publicKeysAreEqual || [pinnedPublicKey isEqualToPublicKey:serverPublicKey];
  }
  if (!publicKeysAreEqual) {
    DebugLog(@"[WARN] Potential \"Man-in-the-Middle\" attack detected since host %@ does not hold the private key corresponding to the public key", host);

    NSDictionary *userDict = @{ @"pinnedPublicKey" : pinnedPublicKey, @"serverPublicKey" : serverPublicKey };
    NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                     reason:@"Certificate could not be verified with provided public key"
                                                   userInfo:userDict];
    @throw exception;
  }

  DebugLog(@"%s publicKeysAreEqual = %@", __PRETTY_FUNCTION__, publicKeysAreEqual ? @"YES" : @"NO");
  // Return success since the server holds the private key
  // corresponding to the public key held bu this security manager.
  NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
  [challenge.sender useCredential:credential forAuthenticationChallenge:challenge];
  completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
}

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
  DebugLog(@"%s connection = %@, challenge = %@", __PRETTY_FUNCTION__, connection, challenge);

  // Normalize the server's host name to lower case.
  NSString *host = [connection.currentRequest.URL.host lowercaseString];
  DebugLog(@"%s Normalized host name = %@", __PRETTY_FUNCTION__, host);

  // Get the PinnedURL for this server.
  ClientCertificate *pinnedClientCertificate = [self clientCertificateForHost:host];
  NSString *authenticationMethod = [[challenge protectionSpace] authenticationMethod];

  // Handle Two-phase mutual client-authentification
  if ([authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate] && pinnedClientCertificate != nil) {
    NSData *p12Data = [NSData dataWithContentsOfURL:pinnedClientCertificate.url];
    if (!p12Data) {
      NSString *reason = [NSString stringWithFormat:@"Certificate data could not be extracted for host = %@.", connection.currentRequest.URL.host];
      NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                       reason:reason
                                                     userInfo:nil];
      @throw exception;
    }

    CFDataRef inPKCS12Data = (__bridge CFDataRef)p12Data;
    SecIdentityRef identity;

    OSStatus result = [self extractIdentity:&identity from:inPKCS12Data with:pinnedClientCertificate.password];
    if (result != noErr) {
      [challenge.sender cancelAuthenticationChallenge:challenge];
      return;
    }

    SecCertificateRef certificate = NULL;
    SecIdentityCopyCertificate(identity, &certificate);
    const void *certificates[] = { certificate };
    CFArrayRef certificatesArray = CFArrayCreate(kCFAllocatorDefault, certificates, 1, NULL);

    // create a credential from the certificate and ideneity, then reply to the challenge with the credential
    NSURLCredential *credential = [NSURLCredential credentialWithIdentity:identity
                                                             certificates:(__bridge NSArray *)certificatesArray
                                                              persistence:NSURLCredentialPersistencePermanent];
    [challenge.sender useCredential:credential forAuthenticationChallenge:challenge];
    return;
  }

  if (![authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
    return [challenge.sender cancelAuthenticationChallenge:challenge];
  }

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

  SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
  if (serverTrust == nil) {
    DebugLog(@"%s FAIL: challenge.protectionSpace.serverTrust is nil", __PRETTY_FUNCTION__);
    return [challenge.sender cancelAuthenticationChallenge:challenge];
  }

  // SecTrustEvaluate performs customary X509
  // checks. Unusual conditions will cause the function to
  // return *non-success*. Unusual conditions include an
  // expired certifcate or self signed certifcate.
  OSStatus status = SecTrustEvaluate(serverTrust, NULL);
  if (status != errSecSuccess) {
    DebugLog(@"%s FAIL: standard TLS validation failed. SecTrustEvaluate returned %@", __PRETTY_FUNCTION__, @(status));
    return [challenge.sender cancelAuthenticationChallenge:challenge];
  }
  DebugLog(@"%s SecTrustEvaluate returned %@", __PRETTY_FUNCTION__, @(status));

  // Get the PinnedURL for this server.
  NSMutableSet<PublicKey *> *pinnedPublicKeys = [self publicKeyForHost:host];

  // It is a logic error (a bug in this SecurityManager class) if this
  // security manager does not have a PinnedURL for this server.
  if (pinnedPublicKeys == nil) {
    NSString *reason = [NSString stringWithFormat:@"LOGIC ERROR: appcelerator.https module bug: SecurityManager could not find a PublicKey for host \"%@\". Please report this issue to us at https://jira.appcelerator.org/browse/MOD-1706", connection.currentRequest.URL.host];
    NSDictionary *userInfo = @{ @"connection" : connection };
    NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                     reason:reason
                                                   userInfo:userInfo];
    @throw exception;
  }
  DebugLog(@"%s host %@ pinned to publicKey %@", __PRETTY_FUNCTION__, host, pinnedPublicKeys);

  CFIndex count = SecTrustGetCertificateCount(serverTrust);
  CFIndex i = 0;
  DebugLog(@"Number of certificates: %ld", count);

  for (i = 0; i < count; i++) {
    SecCertificateRef item = SecTrustGetCertificateAtIndex(serverTrust, i);
    NSString *desc = (NSString *)CFBridgingRelease(CFCopyDescription(item));

    DebugLog(@"%ld: %@", i, desc);
  }

  // Obtain the server's X509 certificate and public key.
  SecCertificateRef serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, pinnedPublicKeys.anyObject.trustChainIndex);
  if (serverCertificate == nil) {
    DebugLog(@"%s FAIL: Could not find the server's X509 certificate in serverTrust", __PRETTY_FUNCTION__);
    return [challenge.sender cancelAuthenticationChallenge:challenge];
  }

  // Create a friendlier Objective-C wrapper around this server's X509
  // certificate.
  X509Certificate *x509Certificate = [X509Certificate x509CertificateWithSecCertificate:serverCertificate andTrustChainIndex:pinnedPublicKeys.anyObject.trustChainIndex];
  if (x509Certificate == nil) {
    // CFBridgingRelease transfer's ownership of the CFStringRef
    // returned by CFCopyDescription to ARC.
    NSString *serverCertificateDescription = (NSString *)CFBridgingRelease(CFCopyDescription(serverCertificate));
    NSString *reason = [NSString stringWithFormat:@"LOGIC ERROR: appcelerator.https module bug: SecurityManager could not create an X509Certificate for host \"%@\" using the SecCertificateRef \"%@\". Please report this issue to us at https://jira.appcelerator.org/browse/MOD-1706", connection.currentRequest.URL.host, serverCertificateDescription];
    NSDictionary *userInfo = @{ @"x509Certificate" : [NSNull null] };
    NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                     reason:reason
                                                   userInfo:userInfo];
    @throw exception;
  }

  DebugLog(@"%s server's X509 certificate = %@", __PRETTY_FUNCTION__, x509Certificate);
  // Get the public key from this server's X509 certificate.
  PublicKey *serverPublicKey = x509Certificate.publicKey;
  if (serverPublicKey == nil) {
    NSString *reason = [NSString stringWithFormat:@"LOGIC ERROR: appcelerator.https module bug: SecurityManager could not find the server's public key for host \"%@\" in the X509 certificate \"%@\". Please report this issue to us at https://jira.appcelerator.org/browse/MOD-1706", connection.currentRequest.URL.host, x509Certificate];
    NSDictionary *userInfo = @{ @"x509Certificate" : x509Certificate };
    NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                     reason:reason
                                                   userInfo:userInfo];
    @throw exception;
  }

  DebugLog(@"%s server's public key = %@", __PRETTY_FUNCTION__, serverPublicKey);

  // Compare the public keys. If they match, then the server is
  // authenticated.
  BOOL publicKeysAreEqual = NO;
  for (PublicKey *pinnedPublicKey in pinnedPublicKeys)
  {
      publicKeysAreEqual = publicKeysAreEqual || [pinnedPublicKey isEqualToPublicKey:serverPublicKey];
  }
  if (!publicKeysAreEqual) {
    DebugLog(@"[WARN] Potential \"Man-in-the-Middle\" attack detected since host %@ does not hold the private key corresponding to the public key.", host);

    NSDictionary *userDict = @{ @"pinnedPublicKeys" : pinnedPublicKeys, @"serverPublicKey" : serverPublicKey };

    NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                     reason:@"Certificate could not be verified with provided public key"
                                                   userInfo:userDict];
    @throw exception;
  }

  DebugLog(@"%s publicKeysAreEqual = %@", __PRETTY_FUNCTION__, publicKeysAreEqual ? @"YES" : @"NO");
  // Return success since the server holds the private key
  // corresponding to the public key held bu this security manager.
  return [challenge.sender useCredential:[NSURLCredential credentialForTrust:serverTrust] forAuthenticationChallenge:challenge];
}

#pragma mark - NSObject

- (BOOL)isEqual:(id)rhs
{
  if (self == rhs) {
    return YES;
  }

  if (![rhs isKindOfClass:[SecurityManager class]]) {
    return NO;
  }

  return [self isEqualToSecurityManager:(SecurityManager *)rhs];
}

- (NSUInteger)hash
{
  return self.pinnedUrlSet.hash;
}

- (NSString *)description
{
  return [NSString stringWithFormat:@"%@: %@", NSStringFromClass(self.class), self.pinnedUrlSet];
}

#pragma mark - Utilities

- (OSStatus)extractIdentity:(SecIdentityRef *)identity from:(CFDataRef)p12Data with:(NSString *)password
{
  OSStatus result = errSecSuccess;

  CFStringRef _password = (__bridge CFStringRef)password;
  const void *keys[] = { kSecImportExportPassphrase };
  const void *values[] = { _password };

  CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);

  CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
  result = SecPKCS12Import(p12Data, options, &items);

  if (result == 0) {
    CFDictionaryRef ident = CFArrayGetValueAtIndex(items, 0);
    const void *tempIdentity = NULL;
    tempIdentity = CFDictionaryGetValue(ident, kSecImportItemIdentity);
    *identity = (SecIdentityRef)tempIdentity;
  }

  if (options) {
    CFRelease(options);
  }

  return result;
}

@end
