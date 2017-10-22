/*!  
  @author Author: Matt Langston
  @copyright Copyright (c) 2014 Appcelerator. All rights reserved.
*/

#import <Foundation/Foundation.h>

// Forward declararion.
@class PublicKey;

/*!
 @discussion
 An Objective-C wrapper around the C interface SecCertificateRef from
 Apple's Security Framework. Instances of this class provide an easier
 to use, and more robust, interface to the SecCertificateRef opaque
 type (a C interface) from Apple's Security Framework. The benefits
 this class provides are:
 
 1. Easier initialization by using a NSURL to a DER encoded X509
    certificate.
 
 2. Automatic memory management with ARC. There is no need to CFRetain
    and CFRelease the underlying SecCertificateRef opaque type.

 3. Container friendly because this class overrides the isEqual and
    hash methods from NSObject such that equality is determined by the
    contents of the instance: two instances are equal if, and only if,
    their actual X509 certificate data is identical. The value of the
    NSURL used to initialize the instances does not factor into the
    implementation of isEqual or hash.

 4. It is immutable, and therefore thread safe.
 
 5. It provides access to the certificate's public key in the form of
    a PublicKey object (which is an Objective-C wrapper around the C
    interface SecKeyRef from Apple's Security Framework).
 
 An easy way to add a DER encoded X509 certificate to your app on Mac
 OS X is to use Safari. Do this by using Safari to visit the trusted
 HTTPS web site, then click the lock icon in the title bar to view the
 sequence of certificates leading from the server's certificate to a
 trusted root. You can then drag a certificate directly to your Xcode
 project (start your drag on the large certificate icon).
 
 This is an example of creating an instances from the DER encoded
 certificate www.foo.com.cer bundled with an app:
 
 NSURL *url = [[NSBundle mainBundle] URLForResource:@"www.foo.com" withExtension: @"cer"];
 X509Certificate *x509Certificate = [X509Certificate X509CertificateWithURL:url];
*/
@interface X509Certificate : NSObject

/*!
 @abstract Convenience factory method to create X509Certificate objects.
 @param secCertificate A SecCertificateRef object.
 @param trustChainIndex An index describing the position of the trust-chain certificate to use.
 @result The X509 certificate wrapper around the SecCertificateRef object
 @throws NSInvalidArgumentException
 @seealso initWithSecCertificate:
 */
+(instancetype)x509CertificateWithSecCertificate:(SecCertificateRef)secCertificate andTrustChainIndex:(NSInteger)trustChainIndex;

/*!
 @abstract Convenience factory method to create X509Certificate objects.
 @param url A URL to a local resource containing a DER encoded X509 certificate.
 @param trustChainIndex An index describing the position of the trust-chain certificate to use.
 @result The X509 certificate contained in the url.
 @throws NSInvalidArgumentException
 @seealso initWithURL:
 */
+(instancetype)x509CertificateWithURL:(NSURL *)url andTrustChainIndex:(NSInteger)trustChainIndex;

/*!
 @abstract Designated initializer. Initialize an instance from a SecCertificateRef.
 @param secCertificate A SecCertificateRef object.
 @param trustChainIndex An index describing the position of the trust-chain certificate to use.
 @result The X509 certificate wrapper around the SecCertificateRef object
 @throws NSInvalidArgumentException
 @seealso X509CertificateWithSecCertificate:
 */
-(instancetype)initWithSecCertificate:(SecCertificateRef)secCertificate andTrustChainIndex:(NSInteger)trustChainIndex;

/*!
 @abstract Initialize an instance from a URL pointing to a DER encoded X509 certificate.
 @param url A URL for a local resource containing a DER encoded X509 certificate.
 @param trustChainIndex An index describing the position of the trust-chain certificate to use.
 @result The X509 certificate contained in the url.
 @throws NSInvalidArgumentException
 @seealso X509CertificateWithURL:
*/
-(instancetype)initWithURL:(NSURL *)url andTrustChainIndex:(NSInteger)trustChainIndex;

/*!
 @abstract The PublicKey contained in the DER encoded X509 certificate.
 */
@property (nonatomic, strong, readonly) PublicKey *publicKey;

/*!
 @abstract The SecCertificateRef contained in the DER encoded X509 certificate used to instantiate this object.
 */
@property (nonatomic, strong, readonly) __attribute__((NSObject)) SecCertificateRef SecCertificate;

/*!
 @abstract The index describing the position of the trust-chain certificate to use.
 */
@property (nonatomic, assign, readonly) NSInteger trustChainIndex;

/*!
 @abstract Compare two instances for value identity.
 @param rhs The instance to compare with (rhs == "right hand side").
 @result TRUE if rhs is equal to this object.
 */
- (BOOL)isEqualToX509Certificate:(X509Certificate *)rhs;

@end
