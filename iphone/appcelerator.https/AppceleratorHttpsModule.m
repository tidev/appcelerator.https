//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "AppceleratorHttpsModule.h"
#import "X509CertificatePinningSecurityManagerProxy.h"

@implementation AppceleratorHttpsModule

- (id)init
{
  self = [super init];
  if (self) {
  }

  return self;
}

- (id)createX509CertificatePinningSecurityManager:(id)args
{
  DebugLog(@"%s args = %@", __PRETTY_FUNCTION__, args);
  id context = ([self executionContext] == nil) ? [self pageContext] : [self executionContext];
  return [[X509CertificatePinningSecurityManagerProxy alloc] _initWithPageContext:context args:args];
}

#pragma mark Internal

- (id)moduleGUID
{
  return @"2163621d-1a78-4215-8244-bda08724ffed";
}

- (NSString *)moduleId
{
  return @"appcelerator.https";
}

@end
