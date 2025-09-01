#!/bin/sh

echo "Waiting for valkey to be ready..."
while ! nc -z valkey 6379; do
  sleep 1
done

MARKER_FILE=/var/lib/dnsblrsd/.blacklist_initialized

if [ ! -f "$MARKER_FILE" ]; then
  echo "Running redis-ctl blacklist initialization..."
  redis-ctl FeedFromDownloads /etc/dnsblrsd/blacklist-sources.json 3M
  touch "$MARKER_FILE"
else
  echo "Blacklist already initialized, skipping redis-ctl"
fi

echo "Starting dnsblrsd"
exec /usr/local/bin/dnsblrsd
