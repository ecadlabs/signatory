#!/usr/bin/env bash

protocol_name="$1"
if [ -z "$protocol_name" ]; then
  echo "Protocol name is required"
  exit 1
fi

# This script:
# - initializes 2 Tezos client configuration 
# - activates 2 sandboxed chains
# - starts a baker on one of the chains. the default chain has a baker running, the second chain is used for manual baking operations
# - initializes some accounts for testing by transferring them balance and configuring the remote signer 

tezos_bin_dir="/usr/local/bin/"
tezos_script_dir="/usr/local/share/tezos"
script_dir="/home/tezos/tezos_scripts"

default_endpoint="http://tezos-node:18731"
manual_baking_endpoint="http://tezos-node-manual-bake:18731"
manual_baking_client_config="/home/tezos/manual-bake-client"
default_signatory="http://signatory:6732"
ec2_signatory="http://10.0.3.122:6732"

client="octez-client"
$client -E $default_endpoint config update
mkdir $manual_baking_client_config
$client -E $manual_baking_endpoint -d $manual_baking_client_config config update

## Sandboxed client ########################################################

# key pairs from $src_dir/test/sandbox.json

#BOOTSTRAP1_IDENTITY="tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx"
#BOOTSTRAP1_PUBLIC="edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav"
BOOTSTRAP1_SECRET="unencrypted:edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh"

#BOOTSTRAP2_IDENTITY="tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN"
#BOOTSTRAP2_PUBLIC="edpktzNbDAUjUk697W7gYg2CRuBQjyPxbEg8dLccYYwKSKvkPvjtV9"
BOOTSTRAP2_SECRET="unencrypted:edsk39qAm1fiMjgmPkw1EgQYkMzkJezLNewd7PLNHTkr6w9XA2zdfo"

#BOOTSTRAP3_IDENTITY="tz1faswCTDciRzE4oJ9jn2Vm2dvjeyA9fUzU"
#BOOTSTRAP3_PUBLIC="edpkuTXkJDGcFd5nh6VvMz8phXxU3Bi7h6hqgywNFi1vZTfQNnS1RV"
BOOTSTRAP3_SECRET="unencrypted:edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ"

#BOOTSTRAP4_IDENTITY="tz1b7tUupMgCNw2cCLpKTkSD1NZzB5TkP2sv"
#BOOTSTRAP4_PUBLIC="edpkuFrRoDSEbJYgxRtLx2ps82UdaYc1WwfS9sE11yhauZt5DgCHbU"
BOOTSTRAP4_SECRET="unencrypted:edsk2uqQB9AY4FvioK2YMdfmyMrer5R8mGFyuaLLFfSRo8EoyNdht3"

#BOOTSTRAP5_IDENTITY="tz1ddb9NMYHZi5UzPdzTZMYQQZoMub195zgv"
#BOOTSTRAP5_PUBLIC="edpkv8EUUH68jmo3f7Um5PezmfGrRF24gnfLpH3sVNwJnV5bVCxL2n"
BOOTSTRAP5_SECRET="unencrypted:edsk4QLrcijEffxV31gGdN2HU7UpyJjA8drFoNcmnB28n89YjPNRFm"

ACTIVATOR_SECRET="unencrypted:edsk31vznjHSSpGExDMHYASz45VZqXN4DPxvsa4hAyY8dHM28cZzp6"

$client import secret key bootstrap1 $BOOTSTRAP1_SECRET || exit 1
$client import secret key bootstrap2 $BOOTSTRAP2_SECRET || exit 1
$client import secret key bootstrap3 $BOOTSTRAP3_SECRET || exit 1
$client import secret key bootstrap4 $BOOTSTRAP4_SECRET || exit 1
$client import secret key bootstrap5 $BOOTSTRAP5_SECRET || exit 1
$client import secret key activator $ACTIVATOR_SECRET || exit 1
#baker1 is used on the manual bake chain for operation kinds test of baking operations. it is an alias for the bootstrap1 account on the manual bake chain
$client -d $manual_baking_client_config import secret key baker1 $default_signatory/tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx || exit 1

protocol_hash=$(grep "^$protocol_name" $script_dir/protocol_hash)
protocol_full_name=$(cat $tezos_script_dir/active_protocol_versions | grep -E '^[0-9]{3}-[A-Za-z]+$' | grep "$protocol_name$")
# Activate the protocol
if [ -z "$protocol_hash" ]; then
  echo "Protocol hash for $protocol_name not found in $script_dir/protocol_hash"
  exit 1
fi
if [ -z "$protocol_full_name" ]; then
  echo "Protocol full name for $protocol_name not found in $tezos_script_dir/active_protocol_versions"
  exit 1
fi
echo $protocol_hash
echo $protocol_full_name
$client -block genesis activate protocol $protocol_hash with fitness 1 and key activator and parameters $tezos_script_dir/$protocol_full_name-parameters/sandbox-parameters.json
$client -E $manual_baking_endpoint -block genesis activate protocol $protocol_hash with fitness 1 and key activator and parameters $tezos_script_dir/$protocol_full_name-parameters/sandbox-parameters.json

# Importing additional keys for testing
# These keys are used in the integration tests and should be imported after the protocol activation.

# alice
$client import secret key alice $default_signatory/tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb
$client --wait none transfer 100000 from bootstrap2 to alice --burn-cap 0.07
$client bake for --minimal-timestamp

# bob
$client import secret key bob $default_signatory/tz1aSkwEot3L2kmUvcoxzjMomb9mvBNuzFK6
$client --wait none transfer 100000 from bootstrap2 to bob --burn-cap 0.07
$client bake for --minimal-timestamp

# opstest
$client import secret key opstest $default_signatory/tz1RKGhRF4TZNCXEfwyqZshGsVfrZeVU446B
$client --wait none transfer 100000 from bootstrap2 to opstest --burn-cap 0.07
$client bake for --minimal-timestamp

# opstest1
$client import secret key opstest1 $default_signatory/tz1R8HJMzVdZ9RqLCknxeq9w5rSbiqJ41szi
$client --wait none transfer 100000 from bootstrap2 to opstest1 --burn-cap 0.07
$client bake for --minimal-timestamp

# tz1alias
$client import secret key tz1alias $default_signatory/tz1dSrM2D7XcWPhdZpDxzNkmVLvdWSxApXaR
$client --wait none transfer 100000 from bootstrap2 to tz1alias --burn-cap 0.07
$client bake for --minimal-timestamp

# tz2alias
$client import secret key tz2alias $default_signatory/tz2QPsZoZse4eeahhg5DdfnBDB4VbU1PwgxN
$client --wait none transfer 100000 from bootstrap2 to tz2alias --burn-cap 0.07
$client bake for --minimal-timestamp

# tz3alias
$client import secret key tz3alias $default_signatory/tz3ZbCsUveF3Q6WUNkThT1wyJyhPunanaAXK
$client --wait none transfer 100000 from bootstrap2 to tz3alias --burn-cap 0.07
$client bake for --minimal-timestamp

# tz4alias
$client import secret key tz4alias $default_signatory/tz4XXtsYav3fZz2FSDa7hcx4F8sh8SaDWNME
$client --wait none transfer 100000 from bootstrap2 to tz4alias --burn-cap 0.07
$client bake for --minimal-timestamp

# tz4pop
$client import secret key tz4pop $default_signatory/tz4Eb1d5L4njHViVgDDkas7qNgoZgDw6VYPz
$client --wait none transfer 1 from bootstrap2 to tz4pop --burn-cap 0.07
$client bake for --minimal-timestamp

# speculos
$client import secret key speculos $default_signatory/tz1RVYaHiobUKXMfJ47F7Rjxx5tu3LC35WSA
$client --wait none transfer 100000 from bootstrap2 to speculos --burn-cap 0.07
$client bake for --minimal-timestamp

$client import secret key nitro $ec2_signatory/tz2Gx28QytbwB9xZYUbc14HrVTJkwwYy4WAk
$client --wait none transfer 100000 from bootstrap2 to nitro --burn-cap 0.07
$client bake for --minimal-timestamp

echo "All keys imported successfully!"

octez-baker run remotely --without-dal --liquidity-baking-toggle-vote pass
