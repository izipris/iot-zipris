#!/bin/bash

sudo mn --custom iot-zipris-topo.py --topo ziprisTopo --controller=remote,ip="$0" --switch ovsk,protocols=OpenFlow13

tok="token.txt"
request_auth="payloads/request_auth.json"
auth=$(curl -sk -H 'Content-Type:application/json' -d '{"login":{"username":"sdn","password":"skyline","domain":"sdn"}}' https://"$0":8443/sdb/v2.0/auth)
echo "$auth" | sed "s/.*\"token\":\([^,}]*\).*/\1/;/^$/d" | tr -d '"' > $tok
token="$([ -f $tok ] && cat $tok)"

