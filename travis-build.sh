#!/bin/bash
set -e
rm -rf *.zip
./gradlew acceptanceTest --stacktrace
#echo "Repeating functional tests with HTTP Basic client authentication"
#./gradlew acceptanceTest -Dhttp.basic=true --stacktrace
./gradlew spring-security-oauth2-provider:gdocs --stacktrace

if [ $TRAVIS_PULL_REQUEST == 'false' ]; then
  echo "Publishing plugin grails-spring-security-core with version $version"

  if [[ $filename != *-SNAPSHOT* && $TRAVIS_REPO_SLUG == 'bluesliverx/grails-spring-security-oauth2-provider' ]]; then
    git config --global user.name "$GIT_NAME"
    git config --global user.email "$GIT_EMAIL"
    git config --global credential.helper "store --file=~/.git-credentials"
    echo "https://$GITHUB_TOKEN:@github.com" > ~/.git-credentials
    git clone https://${GITHUB_TOKEN}@github.com/$TRAVIS_REPO_SLUG.git -b gh-pages gh-pages --single-branch > /dev/null
    cd gh-pages
    git rm -rf .
    cp -r ../docs/. ./
    git add *
    git commit -a -m "Updating docs for Travis build: https://travis-ci.org/$TRAVIS_REPO_SLUG/builds/$TRAVIS_BUILD_ID"
    git push origin HEAD
    cd ..
    rm -rf gh-pages
  else
    echo "Not doing a release, so not publishing docs"
  fi

  # Publish plugin
  ./gradlew spring-security-oauth2-provider:bintrayUpload --stacktrace

fi