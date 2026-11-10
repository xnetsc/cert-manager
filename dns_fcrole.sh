#!/usr/bin/env sh
# shellcheck disable=SC2034
dns_fcrole_info='Alibaba Cloud DNS via FC RAM role (STS, no static keys)
Options:
 CERTS_RAM_ROLE Name of the RAM role bound to the function
'
# Adapted from acme.sh dns_ali.sh (same query builders and signing
# flow). The differences: credentials are fetched fresh from the FC
# metadata endpoint for the function's RAM role, the STS
# SecurityToken joins every signed request, and nothing is saved to
# the acme.sh account config.

Ali_DNS_API="https://alidns.aliyuncs.com/"

dns_fcrole_add() {
  fulldomain=$1
  txtvalue=$2

  _fcrole_credentials || return 1

  _debug "First detect the root zone"
  if ! _get_root "$fulldomain"; then
    return 1
  fi

  _debug "Add record"
  _add_record_query "$_domain" "$_sub_domain" "$txtvalue" && _ali_rest "Add record"
}

dns_fcrole_rm() {
  fulldomain=$1
  txtvalue=$2

  _fcrole_credentials || return 1

  _debug "First detect the root zone"
  if ! _get_root "$fulldomain"; then
    return 1
  fi

  _clean
}

####################  credentials  ####################

_fcrole_credentials() {
  # Function Compute injects the role's STS credentials into the
  # environment; that is the primary source.
  if [ -n "$ALIBABA_CLOUD_ACCESS_KEY_ID" ] && [ -n "$ALIBABA_CLOUD_ACCESS_KEY_SECRET" ]; then
    Ali_Key="$ALIBABA_CLOUD_ACCESS_KEY_ID"
    Ali_Secret="$ALIBABA_CLOUD_ACCESS_KEY_SECRET"
    Ali_Token="$ALIBABA_CLOUD_SECURITY_TOKEN"
    return 0
  fi
  role="${CERTS_RAM_ROLE:-}"
  if [ -z "$role" ]; then
    _err "CERTS_RAM_ROLE is not set."
    return 1
  fi
  meta="http://100.100.100.200/latest/meta-data/ram/security-credentials/$role"
  creds="$(curl -s --max-time 5 "$meta")"
  if [ -z "$creds" ]; then
    _err "Cannot fetch role credentials from the metadata endpoint."
    return 1
  fi
  Ali_Key="$(printf '%s' "$creds" | sed -n 's/.*"AccessKeyId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  Ali_Secret="$(printf '%s' "$creds" | sed -n 's/.*"AccessKeySecret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  Ali_Token="$(printf '%s' "$creds" | sed -n 's/.*"SecurityToken"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  if [ -z "$Ali_Key" ] || [ -z "$Ali_Secret" ] || [ -z "$Ali_Token" ]; then
    _err "Metadata endpoint returned incomplete credentials."
    return 1
  fi
}

####################  Alibaba Cloud common functions  ####################

_ali_rest() {
  act="$1"
  ign="$2"
  mtd="${3:-GET}"

  # The STS token is part of the signed parameter set, encoded the
  # same way dns_ali pre-encodes its Timestamp.
  query=$query'&SecurityToken='$(printf "%s" "$Ali_Token" | _url_encode)

  # The string to sign must carry the parameters in sorted order
  # (the token joined last, so re-sort the assembled pairs).
  query=$(printf "%s" "$query" | tr '&' '\n' | LC_ALL=C sort | paste -sd'&' -)

  signature=$(printf "%s" "$mtd&%2F&$(printf "%s" "$query" | _url_encode upper-hex)" | _hmac "sha1" "$(printf "%s" "$Ali_Secret&" | _hex_dump | tr -d " ")" | _base64)
  signature=$(printf "%s" "$signature" | _url_encode upper-hex)
  url="$endpoint?Signature=$signature"

  if [ "$mtd" = "GET" ]; then
    url="$url&$query"
    response="$(_get "$url")"
  else
    response="$(_post "$query" "$url" "" "$mtd" "application/x-www-form-urlencoded")"
  fi

  _ret="$?"
  _debug2 response "$response"
  if [ "$_ret" != "0" ]; then
    _err "Error <$act>"
    return 1
  fi

  if [ -z "$ign" ]; then
    message="$(echo "$response" | _egrep_o "\"Message\":\"[^\"]*\"" | cut -d : -f 2 | tr -d \")"
    if [ "$message" ]; then
      _err "$message"
      return 1
    fi
  fi
}

_ali_nonce() {
  date +"%s%N" | sed 's/%N//g'
}

_timestamp() {
  date -u +"%Y-%m-%dT%H%%3A%M%%3A%SZ"
}

####################  Private functions below  ####################

_get_root() {
  domain=$1
  i=1
  p=1
  while true; do
    h=$(printf "%s" "$domain" | cut -d . -f "$i"-100)
    if [ -z "$h" ]; then
      _err "root zone lookup failed (token length ${#Ali_Token}); last DNS API response: $(printf '%s' "$response" | head -c 400)"
      return 1
    fi

    _describe_records_query "$h"
    if ! _ali_rest "Get root" "ignore"; then
      return 1
    fi

    if _contains "$response" "PageNumber"; then
      _sub_domain=$(printf "%s" "$domain" | cut -d . -f 1-"$p")
      _debug _sub_domain "$_sub_domain"
      _domain="$h"
      _debug _domain "$_domain"
      return 0
    fi
    p="$i"
    i=$(_math "$i" + 1)
  done
  return 1
}

_check_exist_query() {
  _qdomain="$1"
  _qsubdomain="$2"
  endpoint=$Ali_DNS_API
  query=''
  query=$query'AccessKeyId='$Ali_Key
  query=$query'&Action=DescribeDomainRecords'
  query=$query'&DomainName='$_qdomain
  query=$query'&Format=json'
  query=$query'&RRKeyWord='$_qsubdomain
  query=$query'&SignatureMethod=HMAC-SHA1'
  query=$query"&SignatureNonce=$(_ali_nonce)"
  query=$query'&SignatureVersion=1.0'
  query=$query'&Timestamp='$(_timestamp)
  query=$query'&TypeKeyWord=TXT'
  query=$query'&Version=2015-01-09'
}

_add_record_query() {
  endpoint=$Ali_DNS_API
  query=''
  query=$query'AccessKeyId='$Ali_Key
  query=$query'&Action=AddDomainRecord'
  query=$query'&DomainName='$1
  query=$query'&Format=json'
  query=$query'&RR='$2
  query=$query'&SignatureMethod=HMAC-SHA1'
  query=$query"&SignatureNonce=$(_ali_nonce)"
  query=$query'&SignatureVersion=1.0'
  query=$query'&Timestamp='$(_timestamp)
  query=$query'&Type=TXT'
  query=$query'&Value='$3
  query=$query'&Version=2015-01-09'
}

_delete_record_query() {
  endpoint=$Ali_DNS_API
  query=''
  query=$query'AccessKeyId='$Ali_Key
  query=$query'&Action=DeleteDomainRecord'
  query=$query'&Format=json'
  query=$query'&RecordId='$1
  query=$query'&SignatureMethod=HMAC-SHA1'
  query=$query"&SignatureNonce=$(_ali_nonce)"
  query=$query'&SignatureVersion=1.0'
  query=$query'&Timestamp='$(_timestamp)
  query=$query'&Version=2015-01-09'
}

_describe_records_query() {
  endpoint=$Ali_DNS_API
  query=''
  query=$query'AccessKeyId='$Ali_Key
  query=$query'&Action=DescribeDomainRecords'
  query=$query'&DomainName='$1
  query=$query'&Format=json'
  query=$query'&SignatureMethod=HMAC-SHA1'
  query=$query"&SignatureNonce=$(_ali_nonce)"
  query=$query'&SignatureVersion=1.0'
  query=$query'&Timestamp='$(_timestamp)
  query=$query'&Version=2015-01-09'
}

_clean() {
  _check_exist_query "$_domain" "$_sub_domain"
  if ! _ali_rest "Check exist records" "ignore"; then
    return 1
  fi

  record_id="$(echo "$response" | tr '{' "\n" | grep "$_sub_domain" | grep -- "$txtvalue" | tr "," "\n" | grep RecordId | cut -d '"' -f 4)"
  _debug2 record_id "$record_id"

  if [ -z "$record_id" ]; then
    _debug "record not found, skip"
  else
    _delete_record_query "$record_id"
    _ali_rest "Delete record $record_id" "ignore"
  fi
}
