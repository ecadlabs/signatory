#! /bin/sh

#speculos
#edskRuZGqmXodGDghUhpHV5mfcmfEpA46FLs5kY6QBbyzpfb9JQEwpvrumBroTJ9iyHcY8PKdRAusCLPf7vDRVXhfN8WHE5r8m
#edpktsKqhvR7kXbRWD7yDgLSD7PZUXvjLqf9SFscXhL52pUStF5nQp
#tz1RVYaHiobUKXMfJ47F7Rjxx5tu3LC35WSA

default_protocol=Mumbai
next_protocol_name=Mumbai
next_protocol=PtMumbai2
case "$(basename $0)" in
    "limabox" )
        default_protocol=Lima
        next_protocol_name=Mumbai
        next_protocol=PtMumbai2 ;;
    "mumbaibox" )
        default_protocol=Mumbai
        next_protocol_name=Aplha
        next_protocol=alpha ;;
    "alphabox" )
        default_protocol=Alpha
        next_protocol_name=Failure
        next_protocol=alpha ;;
    * ) ;;
esac

all_commands="
* usage | help | --help | -h: Display this help message."
usage () {
    cat >&2 <<EOF
This script provides a Flextesa “mini-net” sandbox with predefined
parameters useful for tutorials and basic exploration with
wallet software like \`octez-client\`. This one uses the $default_protocol
protocol.

usage: $0 <command>

where <command> may be:
$all_commands
EOF
}

time_bb=${block_time:-5}


export alice="$(flextesa key alice)"
export bob="$(flextesa key bob)"
export speculos="speculos,edpktsKqhvR7kXbRWD7yDgLSD7PZUXvjLqf9SFscXhL52pUStF5nQp,tz1RVYaHiobUKXMfJ47F7Rjxx5tu3LC35WSA,unencrypted:edskRuZGqmXodGDghUhpHV5mfcmfEpA46FLs5kY6QBbyzpfb9JQEwpvrumBroTJ9iyHcY8PKdRAusCLPf7vDRVXhfN8WHE5r8m"
#export b0="$(flextesa key bootacc-0)"
export baker='baker,edpkuFt8yrNyseDKXvMsQ12NTEoqJEnkPQaCp4Kw5WPCEJHr5YV48m,tz1WGcYos3hL7GXYXjKrMnSFdkT7FyXnFBvf,http://signatory:6732/tz1WGcYos3hL7GXYXjKrMnSFdkT7FyXnFBvf'
all_commands="$all_commands
* start : Start a sandbox with the $default_protocol protocol."
root_path=/tmp/mini-box
start () {

    flextesa mini-net \
             --root "$root_path" --size 1 "$@" \
             --keep-root \
             --set-history-mode N000:archive \
             --number-of-b 1 \
             --remove-default-bootstrap-accounts \
             --balance-of-bootstrap-accounts tez:100_000_000 \
             --time-b "$time_bb" \
             --add-bootstrap-account="$alice@2_000_000_000_000" \
             --add-bootstrap-account="$speculos@2_000_000_000_000" \
             --add-bootstrap-account="$bob@2_000_000_000_000" \
             --add-bootstrap-account="$baker@2_000_000_000_000" \
             --no-daemons-for=alice \
             --no-daemons-for=bob \
             --no-daemons-for=speculos \
             --until-level 200_000_000 \
             --protocol-kind "$default_protocol"
 }

all_commands="$all_commands
* start_manual : Start a sandbox with the $default_protocol protocol and NO BAKING."
start_manual () {
    start --no-baking --timestamp-delay=-3600 "$@"
}

all_commands="$all_commands
* bake : Try to bake a block (to be used with 'start_manual' sandboxes)."
bake () {
    octez-client bake for baker0 --minimal-timestamp
}

vote_period=${blocks_per_voting_period:-16}
dummy_props=${extra_dummy_proposals_batch_size:-2}
dummy_levels=${extra_dummy_proposals_batch_levels:-3,5}

all_commands="$all_commands
* start_upgrade : Start a full-upgrade sandbox ($default_protocol -> $next_protocol_name)."
daemons_root=/tmp/daemons-upgrade-box
start_upgrade () {
    flextesa daemons-upgrade \
        --next-protocol-kind "$next_protocol_name" \
        --root-path "$daemons_root" \
        --extra-dummy-proposals-batch-size "$dummy_props" \
        --extra-dummy-proposals-batch-levels "$dummy_levels" \
        --size 2
        --number-of-bootstrap-accounts 3 \ #speculos
        --balance-of-bootstrap-accounts tez:100_000_000 \
        --add-bootstrap-account="$speculos@2_000_000_000_000" \
        --add-bootstrap-account="$alice@2_000_000_000_000" \
        --add-bootstrap-account="$bob@2_000_000_000_000" \
        --no-daemons-for=alice \
        --no-daemons-for=bob \
        --no-daemons-for=speculos \
        --time-between-blocks "$time_bb" \
        --blocks-per-voting-period "$vote_period" \
        --with-timestamp \
        --protocol-kind "$default_protocol" \
        --second-baker octez-baker-"$next_protocol" \
        --test-variant full-upgrade \
        --until-level 200_000_000
}

all_commands="$all_commands
* start_toru : Start a transactional rollup sandbox with the $default_protocol protocol."
root_path=/tmp/mini-box
start_toru() {
    flextesa mini-net \
        --root "$root_path" --size 1 "$@" \
        --set-history-mode N000:archive \
        --number-of-b 2 \
        --balance-of-bootstrap-accounts tez:100_000_000 \
        --time-b "$time_bb" \
        --add-bootstrap-account="$speculos@2_000_000_000_000" \
        --add-bootstrap-account="$alice@2_000_000_000_000" \
        --add-bootstrap-account="$bob@2_000_000_000_000" \
        --no-daemons-for=speculos \        
        --no-daemons-for=alice \
        --no-daemons-for=bob \
        --until-level 200_000_000 \
        --protocol-kind "$default_protocol" \
        --tx-rollup 10:torubox
}

all_commands="$all_commands
* info : Show accounts and information about the sandbox."
info () {
    cat >&2 <<EOF
Usable accounts:
- $(echo $speculos | sed 's/,/\n  * /g')
- $(echo $alice | sed 's/,/\n  * /g')
- $(echo $bob | sed 's/,/\n  * /g')

Root path (logs, chain data, etc.): $root_path (inside container).
EOF
}

all_commands="$all_commands
* initclient : Setup the local octez-client."
initclient () {
    octez-client --endpoint http://localhost:20000 config update
    #I'm not using the octez-client that is on flextesa image. but, I'll put speculos in it's config anyway
    octez-client --protocol Psithaca2MLR import secret key speculos "$(echo $speculos | cut -d, -f 4)" --force
    octez-client --protocol Psithaca2MLR import secret key alice "$(echo $alice | cut -d, -f 4)" --force
    octez-client --protocol Psithaca2MLR import secret key bob "$(echo $bob | cut -d, -f 4)" --force
    octez-client --protocol Psithaca2MLR import secret key baker "$(echo $baker | cut -d, -f 4)" --force
}

all_commands="$all_commands
* toru_info : Show account and information about the trasanctional rollup sandbox."
toru_info() {
    echo '{'
    echo "  \"toru_node_config\":  $(jq . ${root_path}/tx-rollup-torubox/torubox-operator-node-000/data-dir/config.json),"
    echo "  \"turo_ticket_deposit_contract\":  $(jq .[0] ${root_path}/Client-base-C-N000/contracts)"
    echo '}'
}

if [ "$1" = "" ] || [ "$1" = "help" ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    usage
else
    "$@"
fi
