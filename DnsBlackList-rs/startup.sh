#!/bin/sh

while ! nc -z valkey 6379; do
  echo "Waiting for valkey to be ready..."
  sleep 1
done

MARKER_FILE=/var/lib/dnsblrsd/.blacklist_initialized

if [ ! -f "$MARKER_FILE" ]; then
  echo "Running blacklist initialization..."
  while ! /usr/local/bin/redis-ctl /etc/dnsblrsd/dnsblrsd.conf feed-from-downloads /var/lib/dnsblrsd/blacklist_sources.json 3M; do
    echo "Blacklist initialization failed! Retrying in 10 seconds..."
    sleep 10
  done
  touch "$MARKER_FILE"
fi

echo "Starting dnsblrsd"
exec /usr/local/bin/dnsblrsd

