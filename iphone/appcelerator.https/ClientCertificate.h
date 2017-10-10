//
//  ClientCertificate.h
//  appcelerator.https
//
//  Created by Hans Knöchel on 04.10.17.
//  Copyright © 2017 Appcelerator. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ClientCertificate : NSObject {
@private
  NSURL *_url;
  NSString *_passphrase;
}

- (instancetype)initWithURL:(NSURL *)url andPassphrase:(NSString *)passphrase;

@property (nonatomic, strong, readonly) NSURL *url;

@property (nonatomic, copy, readonly) NSString *passphrase;

@end
