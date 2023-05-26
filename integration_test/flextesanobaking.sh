#! /bin/sh

protocol=$1

export opstest='opstest,edpkvSkEEfVMKvAv87env4kMNwLfuLYe7y7wXqgfvrwJwhJJpmL1GB,tz1RKGhRF4TZNCXEfwyqZshGsVfrZeVU446B,http://signatory:6732/tz1RKGhRF4TZNCXEfwyqZshGsVfrZeVU446B'

root_path=/tmp/mini-box

flextesa mini-net \
         --no-baking \
         --root "$root_path" --size 1 \
         --set-history-mode N000:archive \
         --number-of-bootstrap-accounts 0 \
         --remove-default-bootstrap-accounts \
         --time-between-blocks='2,3,2' \
         --add-bootstrap-account="$opstest@2_000_000_000_000" \
         --until-level 200_000_000 \
         --protocol-kind "$protocol"
