#!/bin/bash

if [ $# -ne 1 ] ; then
    echo "USAGE: ./generate_yaml.sh <infile>"
    exit 1
fi

# Compile Python class files from exegesis proto definitions
echo "Compiling Python classes..."
protoc --proto_path=EXEgesis/ --python_out=./ EXEgesis/exegesis/proto/*.proto
protoc --proto_path=EXEgesis/ --python_out=./ EXEgesis/exegesis/proto/pdf/*.proto
protoc --proto_path=EXEgesis/ --python_out=./ EXEgesis/exegesis/proto/x86/*.proto

# Generate YAML
echo "Generating YAML..."
mkdir -p output
python3 proto_to_yaml.py $1
