/**
 * Appcelerator Titanium Mobile
 * Copyright (c) 2014-2015 by Appcelerator, Inc. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */

#import "X509CertificatePinningSecurityManagerProxy.h"
#import "TiHost.h"

@implementation X509CertificatePinningSecurityManagerProxy

typedef NS_ENUM(NSUInteger,ServerConnectionManagerStatus) {
    ServerConnectionManagerStatusSuccess = 0,
    ServerConnectionManagerStatusNoConnection,
    ServerConnectionManagerStatusNoSSLCertFound,
    ServerConnectionManagerStatusWrongSSLCert
};

-(id)_initWithPageContext:(id<TiEvaluator>)context args:(NSArray *)args
{
    ENSURE_TYPE(args, NSArray);

    [self setPinnedUrls:[NSMutableArray array]];
        
    for (NSDictionary *pinnedUrl in [args objectAtIndex:0]) {
        id url = [pinnedUrl valueForKey:@"url"];
        id serverCert = [pinnedUrl valueForKey:@"serverCertificate"];
        
        ENSURE_TYPE(url, NSString);
        ENSURE_TYPE(serverCert, NSString);
        
        [_pinnedUrls addObject:@{
            @"url" : url,
            @"serverCertificate" : [self dataFromFileURL:serverCert]
        }];
    }
    
    return [super _initWithPageContext:context args:args];
}

#pragma mark NSURLSession Delegates

-(void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    if ([[[challenge protectionSpace] authenticationMethod] isEqualToString: NSURLAuthenticationMethodServerTrust]) {
        SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];
        (void) SecTrustEvaluate(serverTrust, NULL);
        
        for (NSDictionary *pinnedUrl in _pinnedUrls) {
            
            if([[pinnedUrl valueForKey:@"url"] isEqualToString:[self currentURL]] == NO) {
                continue;
            }
            
            NSData *serverCert = [pinnedUrl valueForKey:@"serverCertificate"];
            
            SecCertificateRef remoteVersionOfServerCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
            CFDataRef remoteCertificateData = SecCertificateCopyData(remoteVersionOfServerCertificate);
            BOOL certificatesAreTheSame = [serverCert isEqualToData: (__bridge NSData *)remoteCertificateData];
            CFRelease(remoteCertificateData);
            NSURLCredential* cred  = [NSURLCredential credentialForTrust: serverTrust];
            
            // We got a match!
            if (certificatesAreTheSame) {
                completionHandler(NSURLSessionAuthChallengeUseCredential,cred);
                
                // TODO: Call APSHTTPClient onLoad here directly?
                return;
            } else {
                completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace,nil);
                @throw [self createExceptionWithStatus:ServerConnectionManagerStatusWrongSSLCert];
            }
        }
        
        completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace,nil);
        @throw [self createExceptionWithStatus:ServerConnectionManagerStatusNoSSLCertFound];
    }
}

#pragma mark SecurityManagerProtocol Delegates

-(BOOL)willHandleURL:(NSURL *)url
{
    [self setCurrentURL:[url absoluteString]];
    return YES;
}

-(id<APSConnectionDelegate>)connectionDelegateForUrl:(NSURL *)url
{
    return self;
}

#pragma mark Helper

-(NSData*)dataFromFileURL:(NSString*)fileUrl
{
    NSString *resourcesDir = [[NSURL fileURLWithPath:[TiHost resourcePath] isDirectory:YES] path];
    TiFile *file =[[TiFile alloc] initWithPath:[NSString stringWithFormat:@"%@/%@",resourcesDir, fileUrl]];
    
    return [[file blob] data];
}

-(NSException*)createExceptionWithStatus:(int)status
{
    NSString *message = nil;
 
    switch(status) {
        case ServerConnectionManagerStatusNoConnection:
            message = @"No connection available";
            break;
        case ServerConnectionManagerStatusNoSSLCertFound:
            message = @"No matching certificate found";
            break;
        case ServerConnectionManagerStatusWrongSSLCert:
            message = @"Provided certificate does not match server key.";
            break;
        default:
            message = @"Unhandled error occured.";
            break;
    }
    
    return [NSException exceptionWithName:NSInvalidArgumentException reason:message userInfo:@{}];
}

@end

