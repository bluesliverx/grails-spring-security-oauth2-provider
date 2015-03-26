#!/bin/bash
set -e
rm -rf *.zip
./grailsw refresh-dependencies --non-interactive --stacktrace
./grailsw upgrade --non-interactive
./grailsw test-app --non-interactive --stacktrace
./grailsw package-plugin --non-interactive --stacktrace
./grailsw doc --pdf --non-interactive --stacktrace

filename=$(find . -name "grails-*.zip" | head -1)
filename=$(basename $filename)
plugin=${filename:7}
plugin=${plugin/.zip/}
plugin=${plugin/-SNAPSHOT/}
version="${plugin#*-}";
plugin=${plugin/"-$version"/}

if [ $TRAVIS_PULL_REQUEST == 'false' ]; then
  .echo "Publishing plugin grails-spring-security-core with version $version"
  .
  .if [[ $filename != *-SNAPSHOT* && $TRAVIS_REPO_SLUG == 'bluesliverx/grails-spring-security-oauth2-provider' ]]; then
  .  git config --global user.name "$GIT_NAME"
  .  git config --global user.email "$GIT_EMAIL"
  .  git config --global credential.helper "store --file=~/.git-credentials"
  .  echo "https://$GITHUB_TOKEN:@github.com" > ~/.git-credentials
  .  git clone https://${GITHUB_TOKEN}@github.com/$TRAVIS_REPO_SLUG.git -b gh-pages gh-pages --single-branch > /dev/null
  .  cd gh-pages
  .  git rm -rf .
  .  cp -r ../docs/. ./
  .  git add *
  .  git commit -a -m "Updating docs for Travis build: https://travis-ci.org/$TRAVIS_REPO_SLUG/builds/$TRAVIS_BUILD_ID"
  .  git push origin HEAD
  .  cd ..
  .  rm -rf gh-pages
  .else
  .  echo "Not doing a release, so not publishing docs"
  .fi
  .
  .# Publish plugin
  ../grailsw publish-plugin --allow-overwrite --non-interactive --stacktrace

fi