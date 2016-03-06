#!/bin/bash
set -e
rm -rf *.zip
#./gradlew acceptanceTest --stacktrace -P grailsVersions=3.0.11,3.0.12
./gradlew spring-security-oauth2-provider:gdocs --stacktrace

cd spring-security-oauth2-provider/build/libs
filename=$(find . -name "*.jar" | grep -v javadoc | grep -v sources | head -1)
filename=$(basename $filename)
plugin=${filename/spring-security-oauth2-provider-/}
plugin=${plugin/.jar/}
plugin=${plugin/-SNAPSHOT/}
version="${plugin#*-}";
plugin=${plugin/"-$version"/}
cd ../../..

if [ $TRAVIS_PULL_REQUEST == 'false' ]; then
  echo "Publishing plugin grails-spring-security-oauth2-provider with version $version"

  if [[ $filename != *-SNAPSHOT* && $TRAVIS_REPO_SLUG == 'bluesliverx/grails-spring-security-oauth2-provider' ]]; then
    git config --global user.name "$GIT_NAME"
    git config --global user.email "$GIT_EMAIL"
    git config --global credential.helper "store --file=~/.git-credentials"
    echo "https://$GITHUB_TOKEN:@github.com" > ~/.git-credentials

    git clone https://${GITHUB_TOKEN}@github.com/$TRAVIS_REPO_SLUG.git -b gh-pages gh-pages --single-branch > /dev/null
    cd gh-pages
    git rm -rf v3/*
    cp -rp ../spring-security-oauth2-provider/build/docs/. v3/
    git add *
    git commit -a -m "Updating 3.x docs for Travis build: https://travis-ci.org/$TRAVIS_REPO_SLUG/builds/$TRAVIS_BUILD_ID"
    git push origin HEAD
    cd ../..
    rm -rf gh-pages

    # Publish plugin
    ./gradlew spring-security-oauth2-provider:bintrayUpload --stacktrace
  else
    echo "Not doing a release, so not publishing"
  fi

fi