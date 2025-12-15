#!/bin/bash

URLS_FILE=`mktemp`
TAGS_FILE="firefox_release_tags.txt"
LOGLIST_FILE="../../files/mozilla/v3/known_logs_list.json"

CWD=`pwd`
SCRIPT_DIR=`cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd`
cd $SCRIPT_DIR

git restore --staged $TAGS_FILE
git restore $TAGS_FILE
git ls-remote https://github.com/mozilla-firefox/firefox | grep -Eo 'FIREFOX_[0-9_]+_RELEASE' | sed "s/RELEASE//g" | sort -t _ -k 2n | uniq | sed "s/\$/RELEASE/g" > $TAGS_FILE
git add $TAGS_FILE
#git diff --staged -U0 $TAGS_FILE | grep "^+" | grep RELEASE | sed "s/^+/https:\/\/hg-edge.mozilla.org\/mozilla-unified\/raw-file\//g" | sed "s/\$/\/security\/ct\/CTKnownLogs.h/g" | xargs -n 1 go run main.go $LOGLIST_FILE
git diff --staged -U0 $TAGS_FILE | grep "^+" | grep RELEASE | sed "s/^+/https:\/\/raw.githubusercontent.com\/mozilla-firefox\/firefox\/refs\/tags\//g" | sed "s/\$/\/security\/ct\/CTKnownLogs.h/g" | xargs -n 1 go run main.go $LOGLIST_FILE

rm $URLS_FILE
cd $CWD