/*!  
  @author Author: Matt Langston
  @copyright Copyright (c) 2014 Appcelerator. All rights reserved.
*/

#import <Foundation/Foundation.h>

/*!
 @class X509Certificate
 
 @abstract
 
 An X509Certificate is an Objective-C wrapper around the C interface
 SecCertificateRef from Apple's Security Framework.

 @discussion
 
 The X509Certificate class provides an easier to use, and more robust,
 interface to the SecCertificateRef opaque type (a C interface) from
 Apple's Security Framework. The benefits this class provides are:
 
 1. Easier initialization by using a NSURL to a DER encoded X509
    certificate.
 
 2. Automatic memory management with ARC. There is no need to CFRetain
    and CFRelease the underlying SecCertificateRef opaque type.

 3. Container friendly because this class overrides the isEqual and
    hash methods from NSObject such that equality is determined by the
    contents of SecCertificateRef: two X509Certificates are equal if,
    and only if, their actual X509 certificate data is identical. The
    value of the NSURL used to initialize the X509Certificate object
    does not factor into the implementation of isEqual or hash.

 4. It is immutable, and therefore thread safe.
 
 An easy way to add a DER encoded X509 certificate to your app on Mac
 OS X is to use Safari. Do this by using Safari to visit the trusted
 HTTPS web site, then click the lock icon in the title bar to view the
 sequence of certificates leading from the server's certificate to a
 trusted root. You can then drag a certificate directly to your Xcode
 project (start your drag on the large certificate icon).
 
 This is an example of creating an X509Certificate object from the DER
 encoded certificate www.foo.com.cer bundled with an app:
 
 NSURL *url = [[NSBundle mainBundle] URLForResource:@"www.foo.com" withExtension: @"cer"];
 X509Certificate *x509Certificate = [X509Certificate X509CertificateWithURL:url];
*/
@interface X509Certificate : NSObject

/*!
  @function X509CertificateWithURL
  @abstract Convenience factory method to create X509Certificate objects.
  @param url A URL to a local resource containing a DER encoded X509 certificate.
  @result The X509 certificate contained in the url.
  @throws NSInvalidArgumentException
  @seealso initWithURL: @/seealso
 */
+(instancetype)X509CertificateWithURL:(NSURL *)url;

/*!
 @function X509CertificateWithSecCertificate
 @abstract Convenience factory method to create X509Certificate objects.
 @param secCertificate A SecCertificateRef object.
 @result The X509 certificate wrapper around the SecCertificateRef object
 @throws NSInvalidArgumentException
 @seealso initWithSecCertificate: @/seealso
 */
+(instancetype)X509CertificateWithSecCertificate:(SecCertificateRef)secCertificate;

/*!
  @method initWithURL
  @abstract Designated initializer.
  @param url A URL to a local resource containing a DER encoded X509 certificate. 
  @result The X509 certificate contained in the url.
  @throws NSInvalidArgumentException
  @seealso X509CertificateWithURL: @/seealso
*/
-(instancetype)initWithURL:(NSURL *)url;

/*!
 @method initWithSecCertificate
 @abstract Designated initializer.
 @param secCertificate A SecCertificateRef object.
 @result The X509 certificate wrapper around the SecCertificateRef object
 @throws NSInvalidArgumentException
 @seealso X509CertificateWithSecCertificate: @/seealso
 */
-(instancetype)initWithSecCertificate:(SecCertificateRef)secCertificate;

/*!
 @property certificate
 @abstract The SecCertificateRef contained in the DER encoded X509 certificate referred to by the NSURL used to instantiate this object.
 */
@property (nonatomic, strong, readonly) __attribute__((NSObject)) SecCertificateRef certificate;

/*!
 @method isEqualToX509Certificate
 @abstract Compare two X509Certificate objects for value identity.
 @param rhs The X509Certificate to compare with (rhs == "right hand side").
 @result TRUE if rhs is equal to this object.
 */
- (BOOL)isEqualToX509Certificate:(X509Certificate *)rhs;

@end
