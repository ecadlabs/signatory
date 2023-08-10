#! /bin/sh

protocol=$1

export alice="$(flextesa key alice)"
export bob="$(flextesa key bob)"
export speculos="speculos,edpktsKqhvR7kXbRWD7yDgLSD7PZUXvjLqf9SFscXhL52pUStF5nQp,tz1RVYaHiobUKXMfJ47F7Rjxx5tu3LC35WSA,unencrypted:edskRuZGqmXodGDghUhpHV5mfcmfEpA46FLs5kY6QBbyzpfb9JQEwpvrumBroTJ9iyHcY8PKdRAusCLPf7vDRVXhfN8WHE5r8m"
export b0="$(flextesa key bootacc-0)"
export user1="user1,edpkvNSVE2pL4eaCYrew1NEuLi4nnYmwQfe4tdM4NoVgNMEoVCNGoW,tz1QgHGuotVTCmYtA2Mr83FdiWLbwKqUvdnp,unencrypted:edsk3bNBh8s1eovydiRv6YitZHQpBkcS9s9ATQHRZfUQxUKcFU9Mh7"
export tz2alias="tz2alias,sppk7cvVVMRRtYTdriTB6KQqpXZt9TUwSTcpMWq4FwpvG2eVZ56UuHP,tz2QPsZoZse4eeahhg5DdfnBDB4VbU1PwgxN,unencrypted:spsk1XYsTqUsd7LaLs9a8qpmCvLVJeLEZEXkeAZS5dwcKgUZhv3cYw"
#export tz4alias="tz4alias,BLpk1nRV5SBB2QCxsiem5Neoywcizr3mkdp167HL1iKFgFvzPhKo4RSy7J8JBh2BgGgVYjNsRGwU,tz4XXtsYav3fZz2FSDa7hcx4F8sh8SaDWNME,unencrypted:BLsk1XMDG3iepYGj15mBWc7dYjrkpVVM4VH3y5DyBCN9iAGrELwRbY"

root_path=/tmp/mini-box

flextesa mini-net \
         --root "$root_path" --size 1 \
         --set-history-mode N000:archive \
         --number-of-bootstrap-accounts 1 \
         --balance-of-bootstrap-accounts tez:100_000_000 \
         --time-between-blocks='2,3,2' \
         --add-bootstrap-account="$alice@2_000_000_000_000" \
         --add-bootstrap-account="$speculos@2_000_000_000_000" \
         --add-bootstrap-account="$bob@2_000_000_000_000" \
         --add-bootstrap-account="$user1@2_000_000_000_000" \
         --add-bootstrap-account="$tz2alias@2_000_000_000_000" \
         --no-daemons-for=alice \
         --no-daemons-for=bob \
         --no-daemons-for=speculos \
         --no-daemons-for=user1 \
         --no-daemons-for=tz2alias \
         --until-level 200_000_000 \
         --protocol-kind "$protocol"
