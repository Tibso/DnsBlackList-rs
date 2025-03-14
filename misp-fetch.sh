#!/bin/bash

function usage {
  echo "Usage: $0 [-h] -k <misp_api_key> -u <misp_url> -f <out_file>"
}

while getopts 'hk:u:f:' OPT; do
  case "$OPT" in
    h) usage
       exit 0
    ;;
    k) misp_api_key=$OPTARG
    ;;
    u) misp_url=$OPTARG
    ;;
    f) out_file=$OPTARG
    ;;
    *) usage
       exit 1
    ;;
  esac
done

if [[ -z "$misp_api_key" || -z "$misp_url" ]]; then
  echo 'ERR: A required argument is missing'
  exit 1
fi

json="$(curl --fail \
  --header "Authorization: $misp_api_key" \
  --header 'Accept: application/json' \
  --header 'Content-Type: application/json' \
  -d '{
    "returnFormat":"json",
    "type":{"OR":["hostname","domain","domain|ip","ip-dst","ip-src"]},
    "enforceWarninglist": true,
    "to_ids":1,
    "timestamp":"1h"
  }' \
  "$misp_url"
)"
if [[ $? != 0 ]]; then
  echo "ERR: Curl failed with exit code: $?"
  exit $?
fi
if [[ -z "$json" ]]; then
  echo "ERR: MISP API response is empty"
  exit 1
fi
if [[ "$json" == "{}" ]]; then
  exit 0
fi

formatted_banlist="$(echo "$json" | \
jq -r '[.response.Attribute[] | {value,type} |
  if .type == "domain|ip" then
    .value | split("|")[]
  else 
    .value 
  end] |
  unique[]'
)"

if [[ -z "$out_file" ]]; then
  echo "$formatted_banlist"
else
  echo "$formatted_banlist" > "$out_file"
fi

exit 0
