/*!  
  @author Author: Matt Langston
  @copyright Copyright (c) 2014 Appcelerator. All rights reserved.
*/

#import <Foundation/Foundation.h>
#import "X509Certificate.h"

/*!
 @discussion
 An Objective-C wrapper around the C interface SecKeyRef from Apple's
 Security Framework.
 
 This class provides an easier to use, and more robust, interface to
 the SecKeyRef opaque type (a C interface) from Apple's Security
 Framework. The benefits this class provides are:
 
 1. Easier initialization by using an X509Certificate, which is itself
    an Objective-C wrapper around a DER encoded X509 certificate.
 
 2. Automatic memory management with ARC. There is no need to CFRetain
    and CFRelease the underlying SecKeyRef opaque type.

 3. Container friendly because this class overrides the isEqual and
    hash methods from NSObject such that equality is determined by the
    contents of SecKeyRef: two PublicKeys are equal if, and only if,
    their actual RSA public keys are identical. The X509Certificate
    used to initialize the PublicKey object does not factor into the
    implementation of isEqual or hash.

 4. It is immutable, and therefore thread safe.
 
 This is an example of creating a PublicKey object from an
 X509Certificate object (which is itself created from the DER encoded
 certificate www.foo.com.cer bundled with an app):
 
 NSURL *url = [[NSBundle mainBundle] URLForResource:@"www.foo.com" withExtension: @"cer"];
 X509Certificate *x509Certificate = [X509Certificate X509CertificateWithURL:url];
 PublicKey *publicKey = x509Certificate.publicKey;
*/
@interface PublicKey : NSObject

/*!
  @abstract Convenience factory method to create PublicKey objects.
  @param x509Certificate The X509 certificate from which to extract the public key.
  @result The public key from the given X509 certificate, or nil if an exception is thrown
  @throws NSInvalidArgumentException
  @seealso initWithX509Certificate:
 */
+(instancetype)publicKeyWithX509Certificate:(X509Certificate *)x509Certificate;

/*!
  @abstract Designated initializer. Initialize an instance from an X509Certificate.
  @param x509Certificate The X509 certificate from which to extract the public key.
  @throws NSInvalidArgumentException
  @seealso X509CertificateWithURL:
*/
-(instancetype)initWithX509Certificate:(X509Certificate *)x509Certificate;

/*!
 @abstract The X509 certificate used to instantiate this object.
 */
@property (nonatomic, weak, readonly) X509Certificate *x509Certificate;

/*!
 @abstract The SecKeyRef contained in the X509 certificate used to instantiate this object.
 */
@property (nonatomic, strong, readonly) __attribute__((NSObject)) SecKeyRef SecKey;

/*!
 @abstract Compare two instances for value identity.
 @param rhs The instance to compare with (rhs == "right hand side").
 @result TRUE if rhs is equal to this object.
 */
- (BOOL)isEqualToPublicKey:(PublicKey *)rhs;

@end
