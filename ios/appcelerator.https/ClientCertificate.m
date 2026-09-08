//
//  ClientCertificate.m
//  appcelerator.https
//
//  Created by Hans Knöchel on 04.10.17.
//  Copyright © 2017 Appcelerator. All rights reserved.
//

#import "ClientCertificate.h"

@implementation ClientCertificate

- (instancetype)initWithURL:(NSURL *)url andPassword:(NSString *)password
{
  if (self = [super init]) {
    _url = url;
    _password = password;
  }

  return self;
}

- (NSString *)password
{
  return _password;
}

- (NSURL *)url
{
  return _url;
}

@end
