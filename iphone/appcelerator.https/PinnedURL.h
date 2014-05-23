/*!  
  @author Author: Matt Langston
  @copyright Copyright (c) 2014 Appcelerator. All rights reserved.
*/

#import <Foundation/Foundation.h>
#import "PublicKey.h"

/*!
 @class PinnedURL

 @abstract A PinnedURL models the concept of "pinning" an HTTPS
 server's DNS name to it's public key.
 
 @discussion
 
 PinnedURL objects associate a DNS name with the public key contained
 in an X509 certificate.

 Objects of this class are container friendly because the class
 overrides the isEqual and hash methods from NSObject such that
 equality is determined by the combination of the DNS host name and
 the actual RSA public key embedded in an X509 certificate. Two
 PinnedURL objects are equal if, and only if, they contain the same
 DNS host name and RSA public key.

 Objects of this class are also immutable, and are therefore thread
 safe.
*/
@interface PinnedURL : NSObject

/*!
  @function PinnedURLWithURL:andPublicKey:
  @abstract Convenience factory method to create PinnedURL objects.
  @param url The DNS name to pin, which is the host property of the NSURL.
  @param publicKey The public key to pin to the DNS name.
  @result An object associating a DNS name with the publc key contained in an X509 certificate.
  @seealso initWithURL:andPublicKey: @/seealso
 */
+(instancetype)PinnedURLWithURL:(NSURL *)url andPublicKey:(PublicKey *)publicKey;

/*!
  @method initWithURL:andPublicKey:
  @abstract Designated initializer.
  @param url The DNS name to pin, which is the host property of the NSURL.
  @param publicKey The public key to pin to the DNS name.
  @result An object associating a DNS name with the publc key contained in an X509 certificate.
  @seealso PinnedURLWithURL:andPublicKey: @/seealso
*/
-(instancetype)initWithURL:(NSURL *)url andPublicKey:(PublicKey *) publicKey;

/*!
 @property host
 @abstract The host element of the NSURL argument used to instantiate this object.
 */
@property (nonatomic, strong, readonly) NSString *host;

/*!
 @property publicKey
 @abstract The publicKey used to instantiate this object.
 */
@property (nonatomic, strong, readonly) PublicKey *publicKey;

/*!
 @property url
 @abstract The url used to instantiate this object.
 */
@property (nonatomic, strong, readonly) NSURL *url;

/*!
 @method isEqualToPinnedURL
 @abstract Compare two PinnedURL objects for value identity.
 @param rhs The PinnedURL to compare with (rhs == "right hand side").
 @result TRUE if rhs is equal to this object.
 */
- (BOOL)isEqualToPinnedURL:(PinnedURL *)rhs;

@end
