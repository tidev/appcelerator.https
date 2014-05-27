/*!  
  @author Author: Matt Langston
  @copyright Copyright (c) 2014 Appcelerator. All rights reserved.
*/

#import <Foundation/Foundation.h>
#import "TiBase.h"
#import "TiNetworkHTTPClientProxy.h"

/*!
 @discussion
 An instance of this class authenticates a currated set of HTTPS
 servers. It does this by "pinning" an HTTPS server's DNS name to the
 public key contained in the X509 certificate it uses for TLS
 communication. The public key is embedded in an app by adding this
 X509 certificate to the app's Resources directory.

 An instance of this class will guarantee that all TLS connections
 made by NSURLConnection to the pinned DNS name are to a server that
 holds the private key corresponding to the public key embedded in the
 app, therefore authenticating the server.

 This is what prevents the "Man-in-the-Middle" attack.

 Objects of this class are also immutable, and are therefore thread
 safe.

 Instances of this class are container friendly because the class
 overrides the isEqual and hash methods from NSObject such that
 equality is determined by the equality of the set of PinnedURL used
 to construct the instance. Two instances are equal if, and only if,
 they contain the same set of PinnedURL objects.
 */
@interface SecurityManager : NSObject <SecurityManagerProtocol, APSConnectionDelegate>

/*!
  @abstract Convenience factory method to create SecurityManager objects.
  @param pinnedUrlSet The set of PinnedURL objects to enforce.
  @result A SecurityManager that will authenticate the given set of servers using their pinned public keys.
  @seealso initWithX509Certificate:
 */
+(instancetype)securityManagerWithPinnedUrlSet:(NSSet *)pinnedUrlSet;

/*!
  @abstract Designated initializer.
  @param pinnedUrlSet The set of PinnedURL objects to enforce.
  @seealso SecurityManagerWithPinnedURLs:
*/
-(instancetype)initWithPinnedURLs:(NSSet *)pinnedUrlSet;

/*!
 @abstract The set of PinnedURL objects enforced by this SecurityManager.
 @seealso PinnedURL
 */
@property (nonatomic, strong, readonly) NSSet *pinnedUrlSet;

/*!
 @abstract Compare two instances for value identity.
 @param rhs The instance to compare with (rhs == "right hand side").
 @result TRUE if rhs is equal to this object.
 */
- (BOOL)isEqualToSecurityManager:(SecurityManager *)rhs;

@end
