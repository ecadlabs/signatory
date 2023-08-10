#!/bin/bash

#this script is used on a test developer's workstation to get coverage info
#it works on macos

rm -f covraw.txt
go tool covdata textfmt -i=./coverage -o covraw.txt
sed -i '' 's/\/go\/src\/github.com/github.com/g' covraw.txt
rm -f cov.txt
go tool cover -func covraw.txt -o cov.txt
cat cov.txt
rm -f cov.html
go tool cover -html covraw.txt -o cov.html
open cov.html
