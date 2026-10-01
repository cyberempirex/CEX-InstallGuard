#!/usr/bin/env bash
PAYLOAD="ZXhhbXBsZQ=="
printf '%s' "$PAYLOAD" | base64 -d
