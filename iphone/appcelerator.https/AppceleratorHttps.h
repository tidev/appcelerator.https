/*!
 @author Author: Matt Langston
 @copyright Copyright (c) 2014 Appcelerator. All rights reserved.
 */

#ifndef appcelerator_https_AppceleratorHttps_h
#define appcelerator_https_AppceleratorHttps_h

#if defined(NSLog) && defined(APPCELERATOR_HTTPS_DEBUG)
#undef NSLog

/*!
 @discussion
 Titanium defines NSLog as a preprocessor macro for the TiLogMessage
 function. This means that an iOS Titanium proxy created as a Cocoa
 Touch Static Library cannot use NSLog in unit tests beucase of a
 link dependency on Titanium. The work around for this issue is to
 define TiLogMessage as a preprocessor macro for the original NSLog
 function from the Foundation framework.
 
 This is an example of the error link error without the work around.
 
 @textblock
 Undefined symbols for architecture i386:
 "_TiLogMessage", referenced from:
 -[SecurityManagerTests testDesignatedInitializer] in SecurityManagerTests.o
 ld: symbol(s) not found for architecture i386
 clang: error: linker command failed with exit code 1 (use -v to see invocation)
 @/textblock
 */
#define TiLogMessage(...) {\
NSLog(__VA_ARGS__);\
}

#endif //ifdef NSLog

#endif
