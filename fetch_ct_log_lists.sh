#!/bin/bash

echo
echo "Fetching latest Chrome CT log list and verifying its signature:"
wget -nv -O files/gstatic/v3/all_logs_list.json https://www.gstatic.com/ct/log_list/v3/all_logs_list.json
wget -nv -O files/gstatic/v3/all_logs_list.sig https://www.gstatic.com/ct/log_list/v3/all_logs_list.sig
openssl pkeyutl -verify -rawin -pubin -inkey files/gstatic/log_list_pubkey.pem -in files/gstatic/v3/all_logs_list.json -sigfile files/gstatic/v3/all_logs_list.sig
echo

echo "Fetching latest Apple CT log list:"
wget -nv -O files/apple/current_log_list.json https://valid.apple.com/ct/log_list/current_log_list.json
echo