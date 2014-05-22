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
		0xf7,0x64,0x29,0x6b,0xa3,0x69,0x27,0x3c,0x16,0xce,0x9b,0x29,0x74,0x53,0xfd,0x82,0xc3,0xee,0xd9,0xe6
		,0x9a,0x3d,0xec,0x98,0xa3,0x8e,0xed,0xad,0x7f,0x70,0xba,0x3e,0x61,0x72,0x20,0x58,0x2c,0x12,0x2d,0xa7
		,0xa1,0x38,0x22,0xed,0xa8,0x03,0xcb,0x8a	};
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
		0x36,0x80,0xcb,0xf2,0xed,0xbb,0x63,0x39,0x54,0xf4,0x51,0x53,0x8c,0x97,0xe8,0x87,0x6b,0x67,0x46,0x7b
		,0x14,0x3d,0x3a,0x80,0x3b,0xbd,0x80,0x1a,0x2c,0x41,0xee,0x81,0x6b,0x8e,0xd3,0xbb,0x7f,0x0c,0x07,0xba
		,0x06,0x6c,0x8a,0x29,0xc4,0xbc,0x0a,0x7b	};
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
