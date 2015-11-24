/**
 * Appcelerator Titanium Mobile
 * Copyright (c) 2014-2015 by Appcelerator, Inc. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */

#import <Foundation/Foundation.h>
#import "TiBase.h"
#import "TiNetworkHTTPClientProxy.h"
#import "TiUtils.h"

/*!
 @discussion
 A JavaScript interface (aka Titanium proxy) to the SecurityManager.
 
 This Titanium proxy class is simply a JavaScript wrapper for the
 SecurityManager class. It validates the arguments passed from
 JavaScript to the createX509CertificatePinningSecurityManager
 function (defined in AppceleratorHttpsModule) and prevents the use of
 a misconfigured or otherwise invalid SecurityManager.
 
 If argument validation fails, or if the SecurityManager cannot be constructed
 into a known good state, then an exception is thrown which prevents the
 JavaScript code from using a Titanium.Network.HTTPClient without a valid
 SecurityManager. This protects a Titanium developer from accessing an unpinned
 HTTPS URL which they believed to be pinned to a public key.
 
 @seealso AppceleratorHttpsModule
 */
@interface X509CertificatePinningSecurityManagerProxy : TiProxy <SecurityManagerProtocol, NSURLSessionDelegate, NSURLSessionDataDelegate, APSHTTPRequestDelegate, APSConnectionDelegate>

@property(nonatomic, retain) NSMutableArray *pinnedUrls;
@property(nonatomic, assign) NSString *currentUrl;

@end
