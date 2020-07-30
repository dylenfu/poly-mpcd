#!/bin/bash

netprotodir=./net/protos/net
tssprotodir=./net/protos/tss
rm -rf ${netprotodir}/*.pb.go
rm -rf ${tssprotodir}/*.pb.go
protoc --proto_path=$GOPATH/src:. --gogoslick_out=. ${netprotodir}/*.proto
protoc --proto_path=$GOPATH/src:. --gogoslick_out=. ${tssprotodir}/*.proto