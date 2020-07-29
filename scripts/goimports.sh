#!/usr/bin/env bash

goimports -d $(find . -type f -name '*.go' -not -path "./vendor/*")