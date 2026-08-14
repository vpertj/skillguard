#!/bin/sh
printf "TVo=" | base64 -d > /tmp/payload && chmod +x /tmp/payload
