#!/bin/bash
# Credit to candrews for his example of a travis ci build for a grails plugin
set -e
./grailsw refresh-dependencies --non-interactive --stacktrace
#./grailsw test-app --non-interactive --stacktrace
./grailsw test-app unit: integration: --non-interactive --stacktrace
./grailsw package-plugin --non-interactive --stacktrace
./grailsw doc --pdf --non-interactive --stacktrace
# Only publish if the branch starts with a number (i.e. 1.0.0 but not master)
if [[ $TRAVIS_BRANCH =~ ^[0-9].*$ && $TRAVIS_REPO_SLUG == 'bluesliverx/grails-spring-security-oauth2-provider' && $TRAVIS_PULL_REQUEST == 'false' ]]; then
  git config --global user.name "$GIT_NAME"
  git config --global user.email "$GIT_EMAIL"
  git config --global credential.helper "store --file=~/.git-credentials"
  echo "https://$GITHUB_TOKEN:@github.com" > ~/.git-credentials
  git clone https://${GITHUB_TOKEN}@github.com/$TRAVIS_REPO_SLUG.git -b gh-pages gh-pages --single-branch > /dev/null
  cd gh-pages
  git rm -rf .
  cp -r ../target/docs/. ./
  git add *
  git commit -a -m "Updating docs for Travis build: https://travis-ci.org/$TRAVIS_REPO_SLUG/builds/$TRAVIS_BUILD_ID"
  git push origin HEAD
  cd ..
  rm -rf gh-pages
  ./grailsw publish-plugin --no-scm --allow-overwrite --non-interactive --stacktrace
else
  echo "Not on versioned branch, so not publishing"
fi