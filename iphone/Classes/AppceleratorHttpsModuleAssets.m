/**
 * Appcelerator.Https Module - Authenticate server in HTTPS
 * connections made by TiHTTPClient.  This is a generated file. Do not
 * edit or your changes will be lost.
 *
 * Copyright (c) 2014 by Appcelerator, Inc. All Rights Reserved.
 *
 * Licensed under the terms of the Appcelerator Commercial License.
 * Please see the LICENSE included with this distribution for details.
 */

#import "AppceleratorHttpsModuleAssets.h"

extern NSData* filterDataInRange(NSData* thedata, NSRange range);

@implementation AppceleratorHttpsModuleAssets

- (NSData*) moduleAsset
{
	//##TI_AUTOGEN_BEGIN asset

	static UInt8 data[] = {
		0x00,0x4a,0xf1,0x57,0x8f,0x4b,0x1d,0xca,0x5f,0xaa,0x8e,0xeb,0xec,0xe1,0x8b,0x4e,0x3a,0xe3,0x5a,0x8f
		,0x4b,0x4b,0xa0,0x84,0xe4,0x61,0xa5,0xec,0xfc,0xdb,0x69,0x0d,0x29,0xcb,0x28,0xe3,0x57,0xda,0xbd,0xd3
		,0xff,0x2d,0xf6,0xd1,0x4d,0xc8,0x43,0xcb	};
	static NSRange ranges[] = {
		{0,16}
	};
	static NSDictionary *map = nil;
	if (map == nil) {
		map = [[NSDictionary alloc] initWithObjectsAndKeys:
		[NSNumber numberWithInteger:0], @"appcelerator_https_js",
		nil];
	}


	return filterDataInRange([NSData dataWithBytesNoCopy:data length:sizeof(data) freeWhenDone:NO], ranges[0]);
//##TI_AUTOGEN_END asset
}

- (NSData*) resolveModuleAsset:(NSString*)path
{
	//##TI_AUTOGEN_BEGIN resolve_asset

	static UInt8 data[] = {
		0xd8,0x22,0x3d,0x4c,0x1d,0x48,0x8b,0x59,0x53,0xa5,0x3a,0xfb,0x6e,0x3d,0x61,0xe4,0x1f,0x2d,0x44,0xec
		,0x7e,0x6f,0xea,0x05,0x11,0x17,0xa7,0x62,0x44,0x94,0x3d,0xea,0x5b,0x42,0x9b,0x4e,0x25,0x7a,0x25,0x25
		,0x97,0x2b,0x37,0x89,0x30,0xe4,0x1a,0x57	};
	static NSRange ranges[] = {
		{0,16}
	};
	static NSDictionary *map = nil;
	if (map == nil) {
		map = [[NSDictionary alloc] initWithObjectsAndKeys:
		[NSNumber numberWithInteger:0], @"appcelerator_https_js",
		nil];
	}


	NSNumber *index = [map objectForKey:path];
	if (index == nil) {
		return nil;
	}
	return filterDataInRange([NSData dataWithBytesNoCopy:data length:sizeof(data) freeWhenDone:NO], ranges[index.integerValue]);
//##TI_AUTOGEN_END resolve_asset
}

@end
