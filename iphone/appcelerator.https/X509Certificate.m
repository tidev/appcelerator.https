//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "X509Certificate.h"

@interface X509Certificate ()
@end

@implementation X509Certificate

+(instancetype)X509CertificateWithURL:(NSURL *)url {
    X509Certificate *certificate = [[X509Certificate alloc] initWithURL:url];
    return certificate;
}

+(instancetype)X509CertificateWithSecCertificate:(SecCertificateRef)secCertificate {
    X509Certificate *certificate = [[X509Certificate alloc] initWithSecCertificate:secCertificate];
    return certificate;
}

// Designated initializer.
-(instancetype)initWithURL:(NSURL *)url {
    self = [super init];
    if (self) {
        NSDataReadingOptions options = NSDataReadingUncached;
        NSError *error;
        NSData *certificateNSData = [NSData dataWithContentsOfURL:url options:options error:&error];
        if (error) {
            NSString *reason = [NSString stringWithFormat:@"Failed to read certificate data from URL %@", url];
            NSDictionary *userInfo = @{ @"url" : url, @"error" : error };
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }
        
        // __bridge means do not trasfer ownership from Objective-C ARC.
        CFDataRef certificateCFData = (__bridge CFDataRef)certificateNSData;
        _certificate = SecCertificateCreateWithData(NULL, certificateCFData);

        if (_certificate == NULL) {
            NSString *reason = [NSString stringWithFormat:@"Failed to create SecCertificateRef from URL %@", url];
            NSDictionary *userInfo = @{ @"url" : url };
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }
    }
    
    return self;
}

-(instancetype)initWithSecCertificate:(SecCertificateRef)secCertificate {
    self = [super init];
    if (self) {
        _certificate = (SecCertificateRef)CFRetain(secCertificate);
    }
    
    return self;
}

- (void) dealloc {
    CFRelease(_certificate);
}

- (BOOL)isEqualToX509Certificate:(X509Certificate *)rhs {
    if (!rhs) {
        return NO;
    }
    
    BOOL equal = CFEqual(self.certificate, rhs.certificate);
    return equal;
}

#pragma mark - NSObject

- (BOOL)isEqual:(id)rhs {
    if (self == rhs) {
        return YES;
    }
    
    if (![rhs isKindOfClass:[X509Certificate class]]) {
        return NO;
    }
    
    return [self isEqualToX509Certificate:(X509Certificate *)rhs];
}

- (NSUInteger)hash {
    return CFHash(self.certificate);
}

@end
