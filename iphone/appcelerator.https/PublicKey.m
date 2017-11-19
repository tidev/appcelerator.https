//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "PublicKey.h"
#import "AppceleratorHttps.h"

@implementation PublicKey

+(instancetype)publicKeyWithX509Certificate:(X509Certificate *)x509Certificate {
    DebugLog(@"%s", __PRETTY_FUNCTION__);
    return [[PublicKey alloc] initWithX509Certificate:x509Certificate];
}

// Designated initializer.
-(instancetype)initWithX509Certificate:(X509Certificate *)x509Certificate {
    DebugLog(@"%s x509Certificate = %@", __PRETTY_FUNCTION__, x509Certificate);
    self = [super init];
    if (self) {
        if (!(nil != x509Certificate)) {
            NSString *reason = @"x509Certificate must not be nil";
            NSDictionary *userInfo = nil;
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];

            self = nil;
            @throw exception;
        }

        SecPolicyRef policy = NULL;
        SecTrustRef  trust  = NULL;
        @try {
            policy = SecPolicyCreateBasicX509();
            OSStatus status = SecTrustCreateWithCertificates(x509Certificate.SecCertificate, policy, &trust);

            DebugLog(@"%s SecTrustCreateWithCertificates returned %@ for %@", __PRETTY_FUNCTION__, @(status), x509Certificate);

            if (!(errSecSuccess == status)) {
                NSString *reason = [NSString stringWithFormat:@"SecTrustCreateWithCertificates returned result code %@", @(status)];
                NSDictionary *userInfo = @{ @"OSStatus" : @(status) };
                NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                                 reason:reason
                                                               userInfo:userInfo];

                self = nil;
                @throw exception;
            }

            // We need to call SecTrustEvaluate before calling
            // SecTrustCopyPublicKey.
            status = SecTrustEvaluate(trust, NULL);

            DebugLog(@"%s SecTrustEvaluate returned %@", __PRETTY_FUNCTION__, @(status));

            if (!(errSecSuccess == status)) {
                NSString *reason = [NSString stringWithFormat:@"SecTrustEvaluate returned result code %@", @(status)];
                NSDictionary *userInfo = @{ @"OSStatus" : @(status) };
                NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                                 reason:reason
                                                               userInfo:userInfo];

                self = nil;
                @throw exception;
            }

            _SecKey = SecTrustCopyPublicKey(trust);
            _trustChainIndex = x509Certificate.trustChainIndex;

            if (!(NULL != _SecKey)) {
                NSString *reason = @"SecTrustCopyPublicKey returned NULL";
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
            NSString *secKeyDescription = (NSString *)CFBridgingRelease(CFCopyDescription(_SecKey));
            NSLog(@"%s SecTrustCopyPublicKey returned %@", __PRETTY_FUNCTION__, secKeyDescription);
#endif
        }
        @catch (NSException *exception) {
            DebugLog(@"%s caught exception %@", __PRETTY_FUNCTION__, exception);
            // Rethrow the exception so it's handled at a higher level.
            @throw;
        }
        @finally {
            CFRelease(trust);
            CFRelease(policy);
        }
    }

    return self;
}

- (void) dealloc {
    if (_SecKey) {
        CFRelease(_SecKey);
    }
}

- (BOOL)isEqualToPublicKey:(PublicKey *)rhs {
    if (!rhs) {
        return NO;
    }

    BOOL equal = CFEqual(self.SecKey, rhs.SecKey);
    return equal;
}

#pragma mark - NSObject

- (BOOL)isEqual:(id)rhs {
    if (self == rhs) {
        return YES;
    }

    if (![rhs isKindOfClass:[PublicKey class]]) {
        return NO;
    }

    return [self isEqualToPublicKey:(PublicKey *)rhs];
}

- (NSUInteger)hash {
    return CFHash(self.SecKey);
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@: %@", NSStringFromClass(self.class), self.SecKey];
}

@end
