/**
 * Appcelerator.Https Module - Authenticate server in HTTPS connections made by
 * TiHTTPClient.
 *
 * Copyright (c) 2014 by Appcelerator, Inc. All Rights Reserved.
 *
 * Licensed under the terms of the Appcelerator Commercial License.
 * Please see the LICENSE included with this distribution for details.
 */

#import "AppceleratorHttpsModule.h"
#import "TiBase.h"
#import "TiHost.h"
#import "TiUtils.h"

@implementation AppceleratorHttpsModule

#pragma mark Internal

-(id)moduleGUID
{
  return @"62986987-5406-416b-810b-342267fac9af";
}

-(NSString*)moduleId
{
  return @"appcelerator.https";
}

#pragma mark Lifecycle

-(void)startup
{
  [super startup];
}

-(void)shutdown:(id)sender
{
  [super shutdown:sender];
}

#pragma mark Cleanup 

-(void)dealloc
{
  [super dealloc];
}

@end
