#!/usr/bin/env bash
URL="https://example.invalid/tool"
curl "$URL" -o /tmp/tool
chmod +x /tmp/tool
/tmp/tool
