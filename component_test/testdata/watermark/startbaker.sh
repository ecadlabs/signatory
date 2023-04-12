#!/bin/sh
sudo chown -R tezos /home/tezos/.tezos-client
octez-baker-PtMumbai -d /home/tezos/.tezos-client -E http://flextesa:20000 run with local node /home/tezos/.tezos-node baker --liquidity-baking-toggle-vote pass