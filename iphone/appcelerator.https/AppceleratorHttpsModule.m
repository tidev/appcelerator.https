/**
 * Appcelerator Titanium Mobile
 * Copyright (c) 2014-2015 by Appcelerator, Inc. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */

#import "TiBase.h"
#import "AppceleratorHttpsModule.h"
#import "X509CertificatePinningSecurityManagerProxy.h"

@implementation AppceleratorHttpsModule

#pragma mark Internal

-(id)moduleGUID {
    return @"2163621d-1a78-4215-8244-bda08724ffed";
}

-(NSString*)moduleId {
    return @"appcelerator.https";
}

#pragma mark Lifecycle

-(void)startup
{
    [super startup];
    
    NSLog(@"[INFO] %@ loaded",self);
}

-(void)shutdown:(id)sender
{
    [super shutdown:sender];
}

#pragma mark Internal Memory Management

-(void)didReceiveMemoryWarning:(NSNotification*)notification
{
    // optionally release any resources that can be dynamically
    // reloaded once memory is available - such as caches
    [super didReceiveMemoryWarning:notification];
}

#pragma mark Listener Notifications

-(void)_listenerAdded:(NSString *)type count:(int)count
{
    if (count == 1 && [type isEqualToString:@"my_event"])
    {
        // the first (of potentially many) listener is being added
        // for event named 'my_event'
    }
}

-(void)_listenerRemoved:(NSString *)type count:(int)count
{
    if (count == 0 && [type isEqualToString:@"my_event"])
    {
        // the last listener called for event named 'my_event' has
        // been removed, we can optionally clean up any resources
        // since no body is listening at this point for that event
    }
}

-(X509CertificatePinningSecurityManagerProxy*)createX509CertificatePinningSecurityManager:(id)args
{
    return [[X509CertificatePinningSecurityManagerProxy alloc] _initWithPageContext:[self pageContext] args:args];
}

@end
