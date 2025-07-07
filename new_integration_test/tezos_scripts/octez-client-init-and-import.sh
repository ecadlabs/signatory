#!/usr/bin/env bash

/home/tezos/tezos_scripts/octez-init-sandboxed-client.sh 1 tezos-node $1

endpoint='http://tezos-node:18731'

# alice
octez-client -E $endpoint import secret key alice http://signatory:6732/tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb

# bob
octez-client -E $endpoint import secret key bob http://signatory:6732/tz1aSkwEot3L2kmUvcoxzjMomb9mvBNuzFK6

# opstest
octez-client -E $endpoint import secret key opstest http://signatory:6732/tz1RKGhRF4TZNCXEfwyqZshGsVfrZeVU446B

# opstest1
octez-client -E $endpoint import secret key opstest1 http://signatory:6732/tz1R8HJMzVdZ9RqLCknxeq9w5rSbiqJ41szi

# tz2alias
octez-client -E $endpoint import secret key tz2alias http://signatory:6732/tz2QPsZoZse4eeahhg5DdfnBDB4VbU1PwgxN

# tz4alias
octez-client -E $endpoint import secret key tz4alias http://signatory:6732/tz4XXtsYav3fZz2FSDa7hcx4F8sh8SaDWNME
