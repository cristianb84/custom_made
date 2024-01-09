#!/bin/bash

length=$1

if [ -z "$length" ]; then
  echo "Error: Length argument is missing."
  echo "Usage: $0 <length>"
  exit 1
fi

tr -dc 'A-Za-z' < /dev/urandom | head -c $length ; echo
