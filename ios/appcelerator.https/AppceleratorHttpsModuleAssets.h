/*!
 @author Author: Matt Langston
 @copyright Copyright (c) 2014 Appcelerator. All rights reserved.
 */

@interface AppceleratorHttpsModuleAssets : NSObject

- (NSData*) moduleAsset;
- (NSData*) resolveModuleAsset:(NSString*)path;

@end
