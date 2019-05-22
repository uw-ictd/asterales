# Git VCS parameters
VERSION=$(shell git describe)

PROTO_DIRECTORY=./protos/
PROTO_SOURCES=$(shell find $(PROTO_DIRECTORY) -name "*.proto")

PYTHON_OUT_PATH=asterales_protocol/messages/
PYTHON_GEN_FILES=$(basename $(notdir $(PROTO_SOURCES)))
PYTHON_OUTS=$(addprefix $(PYTHON_OUT_PATH), $(addsuffix _pb2.py, $(PYTHON_GEN_FILES)))


protos: python-protos

python-protos:
	$(info proto src is [${PROTO_SOURCES}])
	protoc \
		--proto_path $(PROTO_DIRECTORY) \
		--proto_path /usr/local/include \
		--python_out $(PYTHON_OUT_PATH) \
		$(PROTO_SOURCES)
	$(info PYTHON_GEN_FILES [${PYTHON_OUTS}])
# Change the imports to relative since google does not like multiple
# repositories
# world. https://github.com/protocolbuffers/protobuf/issues/1491
	cd $(PYTHON_OUT_PATH) && sed -i -E 's/^import.*_pb2/from . \0/' *.py

clean-python-protos:
	rm $(PYTHON_OUTS)

.PHONY: clean
clean: clean-python-protos




