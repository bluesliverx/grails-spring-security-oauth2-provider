#!/bin/sh
 
echo "Removing plugin from local Maven cache"
rm -rf $HOME/.m2/repository/org/grails/plugins/spring-security-oauth2-provider
 
echo "Removing previously packaged plugin"
rm -rf grails-spring-security-oauth2-provider-1.0.5-SNAPSHOT.zip
rm -rf grails-spring-security-oauth2-provider-1.0.5-SNAPSHOT.zip.sha1
 
echo "Preparing to build plugin"
./grailsw clean --stacktrace
 
echo "Building plugin and installing to local Maven cache"
./grailsw maven-install --stacktrace
 
echo "Removing previously created test apps"
rm -rf $HOME/Desktop/test-zone/*
 
echo "Creating test apps and running acceptance tests"
./grailsw create-oauth2-test-apps 1.0.5-SNAPSHOT $HOME/.gvm/grails $HOME/.grails $HOME/Desktop/test-zone --stacktrace
 
echo "Finished running tests"