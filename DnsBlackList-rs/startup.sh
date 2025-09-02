#!/bin/sh

while ! nc -z valkey 6379; do
  echo "Waiting for valkey to be ready..."
  sleep 1
done

MARKER_FILE=/var/lib/dnsblrsd/.blacklist_initialized

if [ ! -f "$MARKER_FILE" ]; then
  echo "Running blacklist initialization..."
  /usr/local/bin/redis-ctl /etc/dnsblrsd/dnsblrsd.conf feed-from-downloads /var/lib/dnsblrsd/blacklist_sources.json 3M
  touch "$MARKER_FILE"
fi

echo "Starting dnsblrsd"
/usr/local/bin/dnsblrsd &

tail -f /dev/null
