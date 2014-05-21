# Android Implementation of appcelerator.https Module.

Author: Matt Langston
Date: May 21, 2014

## Building with Eclipse

The appcelerator.https module is built with Maven, which provides for
the automatic generation of Eclipse project files.

If you have already setup your development environment for Maven and
Android then you will only need to follow steps 10 through 14 (below)
in order to generate an Eclipse project.

If you have not setup your development environment for Maven and
Android, then you will need to follow steps 1 through 9, but you'll
only need to do this once.


1. Install Maven 3.2.1

2. Download apache-maven-3.2.1-bin.tar.gz from
   http://maven.apache.org/download.cgi

3. Double-click apache-maven-3.2.1-bin.tar.gz

4. Add these to your .bashrc (you should only need to change
   ANDROID_DOWNLOAD_HOME).

```bash
ANDROID_DOWNLOAD_HOME="/Users/xxx/Documents/Android"
export ANDROID_SDK="${ANDROID_DOWNLOAD_HOME}/adt-bundle-mac-x86_64/sdk"
export ANDROID_NDK="${ANDROID_DOWNLOAD_HOME}/android-ndk-r9d"

\# Required for Android Maven Plugin
export ANDROID_HOME="${ANDROID_SDK}"
export ANDROID_NDK_HOME="${ANDROID_NDK}"

export JAVA_HOME=$(/usr/libexec/java_home)
export PATH="${HOME}/Downloads/maven/apache-maven-3.2.1/bin:$PATH"
export PATH="${PATH}:${ANDROID_SDK}/tools"
export PATH="${PATH}:${ANDROID_SDK}/platform-tools"
```

5. git clone https://github.com/mosabua/maven-android-sdk-deployer.git

6. pushd maven-android-sdk-deployer

7. mvn clean

8. mvn install

9. popd

10. git clone https://github.com/appcelerator-modules/appcelerator.https.git

11. pushd appcelerator.https/android

12. ./mvn_install_titanium_jars.sh

13. mvn clean

14. mvn eclipse:eclipse
