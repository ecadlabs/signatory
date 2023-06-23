#! /bin/sh
go tool covdata textfmt -i=/opt/coverage -o=/opt/coverage/cov.txt
go tool cover -func=/opt/coverage/cov.txt
