#!/bin/bash

git submodule init
mkdir proto_py

protoc --proto_path=EXEgesis/ --python_out=proto_py/ EXEgesis/exegesis/proto/*.proto
protoc --proto_path=EXEgesis/ --python_out=proto_py/ EXEgesis/exegesis/proto/pdf/*.proto
protoc --proto_path=EXEgesis/ --python_out=proto_py/ EXEgesis/exegesis/proto/x86/*.proto
