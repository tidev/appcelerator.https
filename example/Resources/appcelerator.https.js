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

module.exports.createX509CertificatePinningSecurityManager = createX509CertificatePinningSecurityManager;

function createX509CertificatePinningSecurityManager(args) {
	Ti.API.debug('MDL: createX509CertificatePinningSecurityManager');
	return new X509CertificatePinningSecurityManager(args);
};

function X509CertificatePinningSecurityManager(args) {
	Ti.API.debug('MDL: X509CertificatePinningSecurityManager (constructor)');
	this.args = args;
	this.pinnedCertificateList = [];
}

/**
 * Return true if this certificate is valid.
 */
X509CertificatePinningSecurityManager.prototype.pinnedCertificateList = function () {
	Ti.API.debug('MDL: X509CertificatePinningSecurityManager.pinnedCertificateList');
	// TODO
	return this.pinnedCertificateList;
};
