/**
 * Appcelerator Titanium Mobile
 * Copyright (c) 2014-2015 by Appcelerator, Inc. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */

#import "X509CertificatePinningSecurityManagerProxy.h"

@implementation X509CertificatePinningSecurityManagerProxy

typedef NS_ENUM(NSUInteger,ServerConnectionManagerStatus) {
    ServerConnectionManagerStatusSuccess,
    ServerConnectionManagerStatusNoConnection,
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
            @"serverCertificate" : [self dataFromFileUrl:serverCert]
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
            
            if([pinnedUrl valueForKey:@"url"] != _currentUrl) {
                continue;
            }
            
            // TODO: Transform "serverCertificate" filename into NSData
            NSData *serverCert = [NSData dataWithContentsOfFile:[[NSBundle mainBundle]
                                                                 pathForResource:@"server"
                                                                 ofType: @"der"]];
            
            SecCertificateRef remoteVersionOfServerCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
            CFDataRef remoteCertificateData = SecCertificateCopyData(remoteVersionOfServerCertificate);
            BOOL certificatesAreTheSame = [serverCert isEqualToData: (__bridge NSData *)remoteCertificateData];
            CFRelease(remoteCertificateData);
            NSURLCredential* cred  = [NSURLCredential credentialForTrust: serverTrust];
            
            // We got a match!
            if (certificatesAreTheSame) {
                completionHandler(NSURLSessionAuthChallengeUseCredential,cred);
                
                // TODO: Call APSHTTPClient onLoad: callback
                // [self onLoad:ServerConnectionManagerStatusSuccess];
                return;
            } else {
                // TODO: Call APSHTTPClient onError: callback
                completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace,nil);
                // [self onError:ServerConnectionManagerStatusWrongSSLCert];
            }
        }
        
        // No match found: Throw error!
        // TODO: Call APSHTTPClient onError: callback
        // [self onError:ServerConnectionManagerStatusWrongSSLCert];
        completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace,nil);
    }
}

#pragma mark SecurityManagerProtocol Delegates

-(BOOL)willHandleURL:(NSURL *)url
{
    _currentUrl = [url absoluteString];
    return YES;
}

-(id<APSConnectionDelegate>)connectionDelegateForUrl:(NSURL *)url
{
    return self;
}

#pragma mark Helper

-(NSData*)dataFromFileUrl:(NSString*)fileUrl
{
    NSURL *url = [TiUtils toURL:fileUrl proxy:self];
    
    if ([url isFileURL] == NO) {
        NSData *data = [NSData dataWithContentsOfURL:url];
        NSString *ext = [[[url path] lastPathComponent] pathExtension];
        TiFile *tempFile = [TiFile createTempFile:ext];

        [data writeToFile:[tempFile path] atomically:YES];
        url = [NSURL fileURLWithPath:[tempFile path]];
    }
    
    return [NSData dataWithContentsOfURL:url];
}

@end

