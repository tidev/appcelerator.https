//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "PublicKey.h"
#import "X509Certificate.h"

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
        
        SecPolicyRef policy = SecPolicyCreateBasicX509();
        SecTrustRef trust;
        OSStatus status = SecTrustCreateWithCertificates(x509Certificate.certificate, policy, &trust);
        assert(errSecSuccess == status);
        
        // We need to call SecTrustEvaluate before calling
        // SecTrustCopyPublicKey.
        status = SecTrustEvaluate(trust, NULL);
        assert(errSecSuccess == status);
        
        _publicKey = SecTrustCopyPublicKey(trust);
        
        CFRelease(trust);
        CFRelease(policy);
    }

    return self;
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
