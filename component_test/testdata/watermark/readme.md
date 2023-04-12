### Introduction
this folder deploys 3 containers:
1. flextesa mini-net with 1 baker
2. signatory server, the flextesa baker is configured to use signatory for signing
3. octez container, with a baker configured to reproduce double baking

### Run double baking
1. type `make`

### Run just a single baker
1. there are 2 entrypoint to the octez container, one is commented out. toggle the entrypoint to not `runbaker`
2. type `make`

### Increase number of bakers
1. edit the number of `replicas` in the docker-compose file
2. type `make`

### Stop everything and clean up the workspace
1. `make clean`

### Useful commands for troubleshooting

monitor Sigy logs while filtering out healthcheck noise

`docker logs -f signatory 2>&1 | grep -v authorized_keys`

monitor the watermark file on the flextesa baker

`docker exec -it flextesa watch -n 1 cat /tmp/mini-box/Client-base-C-N000/NetXo5iVw1vBo_highwatermarks`

monitor the watermark file on Sigy

`docker exec -it signatory watch -n 1 cat /var/lib/signatory/watermark/NetXo5iVw1vBoxM.json`

monitor the watermark file on the first double baker instance

`docker exec -it doublebake-octez-1 watch -n 1 cat /home/tezos/.tezos-client/NetXo5iVw1vBo_highwatermarks`

query the rpc node

`curl http://localhost:20000/chains/main/blocks/head/header`