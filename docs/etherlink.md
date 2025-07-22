---
id: etherlink
title: Etherlink Signer API
---

## API Calls

### POST /keys/{key}/sequencer_blueprint

Sign the RLP sequencer blueprint

* Input

  Single JSON hexadecimal string containing unsigned sequencer blueprint

* Output

  ```json
  {
      "signature": "...", // Base58 encoded signature
      "signed_sequencer_blueprint": "..." // Hexadecimal string containing RLP encoded signed blueprint
  }
  ```

### POST /keys/{key}/sequencer_signal

Sign the RLP sequencer signal aka DAL slot import signals

* Input

  Single JSON hexadecimal string containing unsigned DAL slot import signals list

* Output

  ```json
  {
      "signature": "...", // Base58 encoded signature
      "signed_sequencer_signal": "..." // Hexadecimal string containing RLP encoded signed DAL slot import signals list
  }
  ```

## Key Policy

There are two special request types `sequencer_blueprint` and `sequencer_signal` to be used to enable those calls for specific keys
