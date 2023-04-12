all: clean up

.PHONY: clean
clean: down
	rm -rf .baker-client/*
	rm -rf .tezos-node/*

.PHONY: down
down:
	docker compose down

.PHONY: up
up:
	docker compose up -d

#docker logs -f signatory 2>&1 | grep -v authorized_keys
#docker exec -it flextesa watch -n 1 cat /tmp/mini-box/Client-base-C-N000/NetXo5iVw1vBo_highwatermarks
#docker exec -it signatory watch -n 1 cat /var/lib/signatory/watermark/NetXo5iVw1vBoxM.json