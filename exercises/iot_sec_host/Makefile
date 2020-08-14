BMV2_SWITCH_EXE = simple_switch_grpc
TOPO = topology/topology.json

BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

P4C = p4c-bm2-ss

RUN_SCRIPT = init.py

source = $(wildcard *.p4)
compiled_json := $(source:.p4=.json)


all: run

run: build
    $(P4C) switch.p4 --p4runtime-files build/switch.p4info.txt -o build/switch.json
    $(P4C) router.p4 --p4runtime-files build/router.p4info.txt -o build/router.json
    $(P4C) security_switch.p4 --p4runtime-files build/security_switch.p4info.txt -o build/security_switch.json
	sudo python $(RUN_SCRIPT) -t $(TOPO) -b $(BMV2_SWITCH_EXE)

stop:
	sudo mn -c

build: dirs $(compiled_json)

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

