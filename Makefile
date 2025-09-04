all: run

run:
	@docker compose down
	@docker compose build
	@docker compose up -d

build:
	@docker compose down
	@docker compose build

logs:
	@docker compose logs -f dnsblrsd valkey

start:
	@docker compose start

stop:
	@docker compose stop

godnsblrsd:
	@docker exec -it dnsblrsd sh

govalkey:
	@docker exec -it valkey sh

.PHONY: run build stop start logs build godnsblrsd govalkey

