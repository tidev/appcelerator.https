#! /usr/bin/env bash

# Author: Matt Langston
# Date: 2014.05.21
#
# This script installs the required Titanium Android jars into your
# local Maven repository. The only variable you may need to edit is
# TITANIUM_SDK_VERSION.

TITANIUM_SDK_VERSION="3.3.0"
TITANIUM_SDK="${HOME}/Library/Application Support/Titanium/mobilesdk/osx/${TITANIUM_SDK_VERSION}"

function echo_and_eval {
    local -r cmd="${1:?}"
    echo "${cmd}" && eval "${cmd}"
}

for jar_name in kroll-apt.jar kroll-common.jar titanium.jar modules/titanium-network.jar; do
	artifactId="$(basename ${jar_name} .jar)"
	version="${TITANIUM_SDK_VERSION}"
	cmd="mvn install:install-file -Dfile=\"${TITANIUM_SDK}/android/${jar_name}\" -DgroupId=com.appcelerator -DartifactId=${artifactId} -Dversion=${version} -Dpackaging=jar"
	echo_and_eval "${cmd}"
done
