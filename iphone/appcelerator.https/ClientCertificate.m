//
//  ClientCertificate.m
//  appcelerator.https
//
//  Created by Hans Knöchel on 04.10.17.
//  Copyright © 2017 Appcelerator. All rights reserved.
//

#import "ClientCertificate.h"

@implementation ClientCertificate

- (instancetype)initWithURL:(NSURL *)url andPassphrase:(NSString *)passphrase {
  if (self = [super init]) {
    _url = url;
    _passphrase = passphrase;
  }
  
  return self;
}

- (NSString *)passphrase {
  return _passphrase;
}

- (NSURL *)url {
  return _url;
}

@end
