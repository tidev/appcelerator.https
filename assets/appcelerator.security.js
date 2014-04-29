/**
 * Author: Matt Langston <mlangston@appcelerator.com>
 * Created: 2014.04.28
 * 
 * Copyright (c) 2014 by Appcelerator, Inc. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this software or any of it's contents except in
 * compliance with the License. The full text of the license is in the
 * file LICENSE.txt in the top-level directory of this project, or you
 * may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 */

"use strict";

module.exports.ServerCertificate;

function ServerCertificate(certificatePath) {
	this.certificatePath = certificatePath;
	this.dnsNameList = [];
}

/**
 * Return true if this certificate is valid.
 */
ServerCertificate.prototype.isValid = function () {
	return false;
};

/**
 * Return the list of DNS names that this certificate is pinned to.
 */
ServerCertificate.prototype.dnsNameList = function () {
	// TODO
	return this.dnsNameList;
};
