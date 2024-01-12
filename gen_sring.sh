#!/bin/bash

usage() {
  echo "Usage: $0 <length> [-l | -d]"
  echo "  -l: Generate a string with only letters (A-Za-z)."
  echo "  -d: Generate a string with only digits (0-9)."
  exit 1
}

if [ $# -eq 0 ]; then
  usage
fi

length=$1
shift
charset="A-Za-z0-9"

while getopts "ld" opt; do
  case $opt in
    l)
      charset="A-Za-z"
      ;;
    d)
      charset="0-9"
      ;;
    *)
      usage
      ;;
  esac
done

tr -dc "$charset" < /dev/urandom | head -c $length ; echo
