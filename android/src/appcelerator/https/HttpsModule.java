/**
 * Appcelerator.Https Module - Authenticate server in HTTPS
 * connections made by TiHTTPClient.
 *
 * Copyright (c) 2014 by Appcelerator, Inc. All Rights Reserved.
 *
 * Licensed under the terms of the Appcelerator Commercial License.
 * Please see the LICENSE included with this distribution for details.
 */
package appcelerator.https;

import org.appcelerator.kroll.KrollModule;
import org.appcelerator.kroll.annotations.Kroll;

import org.appcelerator.titanium.TiApplication;
import org.appcelerator.kroll.common.Log;

@Kroll.module(name="https", id="appcelerator.https")
public class HttpsModule extends KrollModule
{
	// Standard Debugging variables
	private static final String TAG = "HttpsModule";
	
	public HttpsModule()
	{
		super();
	}
	
	@Kroll.onAppCreate
	public static void onAppCreate(TiApplication app)
	{
		// TODO
	}
}

