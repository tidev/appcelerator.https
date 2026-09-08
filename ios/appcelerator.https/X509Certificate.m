//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "X509Certificate.h"
#import "AppceleratorHttps.h"
#import "PublicKey.h"

@implementation X509Certificate

@synthesize publicKey = _publicKey;

+ (instancetype)x509CertificateWithSecCertificate:(SecCertificateRef)secCertificate andTrustChainIndex:(NSInteger)trustChainIndex
{
  DebugLog(@"%s", __PRETTY_FUNCTION__);
  return [[X509Certificate alloc] initWithSecCertificate:secCertificate andTrustChainIndex:trustChainIndex];
}

+ (instancetype)x509CertificateWithURL:(NSURL *)url andTrustChainIndex:(NSInteger)trustChainIndex
{
  DebugLog(@"%s", __PRETTY_FUNCTION__);
  return [[X509Certificate alloc] initWithURL:url andTrustChainIndex:trustChainIndex];
}

// Designated initializer.
- (instancetype)initWithSecCertificate:(SecCertificateRef)secCertificate andTrustChainIndex:(NSInteger)trustChainIndex
{
  self = [super init];
  if (self) {
    // The certificate must not be NULL.
    if (!(NULL != secCertificate)) {
      NSString *reason = @"secCertificate must not be nil";
      NSDictionary *userInfo = nil;
      NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                       reason:reason
                                                     userInfo:userInfo];

      self = nil;
      @throw exception;
    }

#ifdef DEBUG
    // CFBridgingRelease transfer's ownership of the CFStringRef
    // returned by CFCopyDescription to ARC.
    NSString *secCertificateDescription = (NSString *)CFBridgingRelease(CFCopyDescription(secCertificate));
    NSLog(@"%s secCertificate = %@", __PRETTY_FUNCTION__, secCertificateDescription);
#endif

    _SecCertificate = (SecCertificateRef)CFRetain(secCertificate);
    _trustChainIndex = trustChainIndex;
  }

  return self;
}

- (instancetype)initWithURL:(NSURL *)url andTrustChainIndex:(NSInteger)trustChainIndex
{
  DebugLog(@"%s url = %@", __PRETTY_FUNCTION__, url);
  // The URL must not be nill
  if (!(nil != url)) {
    NSString *reason = @"url must not be nil";
    NSDictionary *userInfo = nil;
    NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                     reason:reason
                                                   userInfo:userInfo];
    @throw exception;
  }

  // The URL must contain data.
  NSDataReadingOptions options = NSDataReadingUncached;
  NSError *error;
  NSData *certificateNSData = [NSData dataWithContentsOfURL:url options:options error:&error];
  if (!(nil == error)) {
    NSString *reason = [NSString stringWithFormat:@"Failed to read certificate data from URL %@", url];
    NSDictionary *userInfo = @{ @"url" : url, @"error" : error };
    NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                     reason:reason
                                                   userInfo:userInfo];
    @throw exception;
  }

  DebugLog(@"%s dataWithContentsOfURL returned %@ bytes", __PRETTY_FUNCTION__, @(certificateNSData.length));

  // __bridge means do not transfer ownership from Objective-C ARC.
  CFDataRef certificateCFData = (__bridge CFDataRef)certificateNSData;

  // Call the designated initializer.
  SecCertificateRef certificate;
  @try {
    certificate = SecCertificateCreateWithData(NULL, certificateCFData);
    self = [self initWithSecCertificate:certificate andTrustChainIndex:trustChainIndex];
  }
  @finally {
    CFRelease(certificate);
  }

  return self;
}

- (void)dealloc
{
  if (_SecCertificate) {
    CFRelease(_SecCertificate);
  }
}

// The publicKey getter has to be written manually because it requires this
// object (i.e. an X509Certificate object) for initialization, meaning that
// it can be constructed in the X509Certificate designated initializer.
- (PublicKey *)publicKey
{
  if (nil == _publicKey) {
    _publicKey = [PublicKey publicKeyWithX509Certificate:self];
  }

  return _publicKey;
}

- (BOOL)isEqualToX509Certificate:(X509Certificate *)rhs
{
  if (!rhs) {
    return NO;
  }

  BOOL equal = CFEqual(self.SecCertificate, rhs.SecCertificate);
  return equal;
}

#pragma mark - NSObject

- (BOOL)isEqual:(id)rhs
{
  if (self == rhs) {
    return YES;
  }

  if (![rhs isKindOfClass:[X509Certificate class]]) {
    return NO;
  }

  return [self isEqualToX509Certificate:(X509Certificate *)rhs];
}

- (NSUInteger)hash
{
  return CFHash(self.SecCertificate);
}

- (NSString *)description
{
  // CFBridgingRelease transfer's ownership of the CFStringRef
  // returned by CFCopyDescription to ARC.
  NSString *secCertificateDescription = (NSString *)CFBridgingRelease(CFCopyDescription(self.SecCertificate));
  return [NSString stringWithFormat:@"%@: %@", NSStringFromClass(self.class), secCertificateDescription];
}

@end
