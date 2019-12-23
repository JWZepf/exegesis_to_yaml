# exegesis_to_yaml
This project is an extension of Google's [EXEgesis](https://github.com/google/exegesis) by converting the generated architecture information from protobuf's `pbtxt` format into YAML's `yml` format. 

## Usage
To use this converter, clone the EXEgesis submodule and follow the instructions located in the EXEgesis [README](https://github.com/google/EXEgesis/tree/master/exegesis/tools) to generate the architecture information. As an alternative I have included a copy of this data created from the Intel manual in December 2019 located at `data/intel_instruction_set.pbtxt`. 

Once the architecture data has been generated, convert the `pbtxt` format to `yml` using the following command:
```
./generate_yaml.sh <path_to_architecture_info_pbtxt>
```

The `generate_yaml.sh` script will compile the `.proto` definitions in EXEgesis into Python classes and then run the `proto_to_yaml.py` Python script to generate the YAML. The resulting file will be located at `output/arch.yml`
