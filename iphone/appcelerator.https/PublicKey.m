//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "PublicKey.h"

@interface PublicKey ()
@end


@implementation PublicKey

+(instancetype)PublicKeyWithX509Certificate:(X509Certificate *)x509Certificate {
    PublicKey *publicKey = [[PublicKey alloc] initWithX509Certificate:x509Certificate];
    return publicKey;
}

// Designated initializer.
-(instancetype)initWithX509Certificate:(X509Certificate *)x509Certificate {
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
            OSStatus status = SecTrustCreateWithCertificates(x509Certificate.certificate, policy, &trust);
            //assert(errSecSuccess == status);
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
            //assert(errSecSuccess == status);
            if (!(errSecSuccess == status)) {
                NSString *reason = [NSString stringWithFormat:@"SecTrustEvaluate returned result code %@", @(status)];
                NSDictionary *userInfo = @{ @"OSStatus" : @(status) };
                NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                                 reason:reason
                                                               userInfo:userInfo];
                
                self = nil;
                @throw exception;
            }
            
            _publicKey = SecTrustCopyPublicKey(trust);
            if (!(NULL != _publicKey)) {
                NSString *reason = @"SecTrustCopyPublicKey returned NULL";
                NSDictionary *userInfo = nil;
                NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                                 reason:reason
                                                               userInfo:userInfo];
                
                self = nil;
                @throw exception;
            }
        }
        @catch (NSException *exception) {
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
    if (_publicKey) {
        CFRelease(_publicKey);
    }
}

- (BOOL)isEqualToPublicKey:(PublicKey *)rhs {
    if (!rhs) {
        return NO;
    }
    
    BOOL equal = CFEqual(self.publicKey, rhs.publicKey);
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
    return CFHash(self.publicKey);
}

@end
