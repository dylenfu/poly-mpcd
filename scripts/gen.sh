#!/bin/bash

protodir=./net/protos
rm -rf ${protodir}/*.pb.go
protoc --proto_path=$GOPATH/src:. --gogoslick_out=. ${protodir}/*.proto