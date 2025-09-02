all: run

run:
	@docker compose down
	@docker compose build
	@docker compose up -d
	@docker logs -f dnsblrsd

stop:
	@docker compose down

exec:
	@docker exec -it dnsblrsd /bin/bash

.PHONY: run stop

