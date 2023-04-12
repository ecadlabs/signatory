#!/bin/sh

docker logs -f signatory 2>&1 | grep -v authorized_keys >./scraped_data/sigy.log
