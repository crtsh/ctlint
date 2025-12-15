#!/bin/bash

LOGLIST=$(mktemp)
LOGLISTSIG=$(mktemp)

echo
mkdir -p files/gstatic/v3
wget -nv -O "$LOGLIST" https://www.gstatic.com/ct/log_list/v3/all_logs_list.json
if [ $? -eq 0 ]; then
  wget -nv -O "$LOGLISTSIG" https://www.gstatic.com/ct/log_list/v3/all_logs_list.sig
  if [ $? -eq 0 ]; then
    openssl pkeyutl -verify -rawin -pubin -inkey files/gstatic/log_list_pubkey.pem -in "$LOGLIST" -sigfile "$LOGLISTSIG"
    if [ $? -eq 0 ]; then
      mv "$LOGLIST" files/gstatic/v3/all_logs_list.json
      mv "$LOGLISTSIG" files/gstatic/v3/all_logs_list.sig
    else
      echo "Signature verification failed for https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
    fi
  else
    echo "Failed to download signature file"
  fi
else
  echo "Failed to download log list"
fi

echo
mkdir -p files/apple
wget -nv -O "$LOGLIST" https://valid.apple.com/ct/log_list/current_log_list.json
if [ $? -eq 0 ]; then
  mv "$LOGLIST" files/apple/current_log_list.json
else
  echo "Failed to download log list"
fi

echo
mkdir -p files/crtsh/v3
wget -nv -O "$LOGLIST" https://crt.sh/v3/logs.json?include=all
if [ $? -eq 0 ]; then
  mv "$LOGLIST" files/crtsh/v3/all_logs_list.json
else
  echo "Failed to download log list"
fi

echo
cmd/mozillactknownlogs/check_for_ctknownlogs_changes.sh

echo
