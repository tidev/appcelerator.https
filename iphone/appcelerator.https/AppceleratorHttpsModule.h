/*!
 @author Author: Matt Langston
 @copyright Copyright (c) 2014 Appcelerator. All rights reserved.
 */

#import "TiModule.h"

/*!
 @class AppceleratorHttpsModule
 
 @abstract
 
 A AppceleratorHttpsModule is a Titanium module for creating a SecurityManager
 that "pins" an HTTPS server's DNS name to the public key contained in the X509
 certificate it uses for TLS communication. The public key is embedded in an app
 by adding this X509 certificate to the app's Resources directory.
 
 @discussion
 
 This Titanium module class exposes a single function to JavaScript, namely the
 createX509CertificatePinningSecurityManager function. This function simply 
 creates and returns an instance of X509CertificatePinningSecurityManagerProxy.
 
 @seealso X509CertificatePinningSecurityManagerProxy: @/seealso
 */
@interface AppceleratorHttpsModule : TiModule

// This class provides no API for Objecive-C developers. All of this classes
// functionality is accessed from JavaScript and is only meant to be used in a
// Titanium application

@end
