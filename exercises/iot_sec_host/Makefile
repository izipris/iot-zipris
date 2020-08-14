BMV2_SWITCH_EXE = simple_switch_grpc
TOPO = topology/topology.json

BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

P4C = p4c-bm2-ss

RUN_SCRIPT = ../../utils/run_exercise.py

all: run

run:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
	$(P4C) switch.p4 --p4runtime-files build/switch.p4info.txt -o build/switch.json
	$(P4C) router.p4 --p4runtime-files build/router.p4info.txt -o build/router.json
	$(P4C) security_switch.p4 --p4runtime-files build/security_switch.p4info.txt -o build/security_switch.json
	sudo python $(RUN_SCRIPT) -t $(TOPO) $(run_args)

stop:
	sudo mn -c

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

