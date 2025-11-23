#!/bin/sh
set -e

if [ -z "$DOMAIN" ]; then
    echo "Error: DOMAIN environment variable is not set."
    echo "Usage: docker run -e DOMAIN=https://your-domain.com -p 80:80 shinde11/nat-info"
    exit 1
fi

# Remove trailing slash if present to avoid double slashes
DOMAIN=$(echo "$DOMAIN" | sed 's:/*$::')

echo "Generating index.html (install script) with domain: $DOMAIN"

# Replace placeholder and save as index.html so it's served at root
sed "s|{{DOMAIN}}|${DOMAIN}|g" /usr/share/nginx/html/install.sh.template > /usr/share/nginx/html/index.html

# Execute the CMD (nginx)
exec "$@"
