//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "PinnedURL.h"
#import "AppceleratorHttps.h"

@implementation PinnedURL

+(instancetype)pinnedURLWithURL:(NSURL *)url andPublicKey:(PublicKey *)publicKey {
    DebugLog(@"%s", __PRETTY_FUNCTION__);
    return [[PinnedURL alloc] initWithURL:url andPublicKey:publicKey];
}

// Designated initializer.
-(instancetype)initWithURL:(NSURL *)url andPublicKey:(PublicKey *) publicKey {
    DebugLog(@"%s url = %@, publicKey = %@", __PRETTY_FUNCTION__, url, publicKey);
    self = [super init];
    if (self) {
        if (!(nil != url)) {
            NSString *reason = @"url must not be nil";
            NSDictionary *userInfo = nil;
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }

        if (!(nil != publicKey)) {
            NSString *reason = @"publicKey must not be nil";
            NSDictionary *userInfo = nil;
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];
            
            self = nil;
            @throw exception;
        }

        _url = [url copy];

        // The scheme must be https. Note the use of
        // localizedCaseInsensitiveCompare, which is a secure coding practice
        // since URL components are case-insensitive as described in RFCs 1808,
        // 1738, and 2732.
        if ([_url.scheme localizedCaseInsensitiveCompare:@"https"] != NSOrderedSame) {
            NSString *reason = [NSString stringWithFormat:@"Scheme must be https for URL %@", _url];
            NSDictionary *userInfo = @{ @"url" : _url };
            NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                             reason:reason
                                                           userInfo:userInfo];

            self = nil;
            @throw exception;
        }

        _publicKey = publicKey;
        _host = url.host;
    }
    
    return self;
}

- (BOOL)isEqualToPinnedURL:(PinnedURL *)rhs {
    if (!rhs) {
        return NO;
    }
    
    BOOL equal = [self.host localizedCaseInsensitiveCompare:rhs.host] == NSOrderedSame && [self.publicKey isEqualToPublicKey:rhs.publicKey];
    
    return equal;
}

#pragma mark - NSObject

- (BOOL)isEqual:(id)rhs {
    if (self == rhs) {
        return YES;
    }
    
    if (![rhs isKindOfClass:[PinnedURL class]]) {
        return NO;
    }
    
    return [self isEqualToPinnedURL:(PinnedURL *)rhs];
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = 17;
    result *= prime + self.host.hash;
    result *= prime + self.publicKey.hash;
    return result;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@: %@, %@", NSStringFromClass(self.class), self.host, self.publicKey];
}

@end
