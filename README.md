# iot-zipris

## Overview


## Prerequisites
<ul>
<li>Setup a Mininet environment on a VM (<a href="http://mininet.org/download/">see instructions</a>). If you're using Windows on your local machine, consider working with <a href="https://www.youtube.com/watch?v=YLAYfwUPj7s">PuTTY & Xming</a> in order to enable <i>xterm</i> usage in Mininet</li>
<li>Setup HPE VAN SDN Controller on a separated VM (<a href="https://www.youtube.com/watch?v=_xWwKLjZ4Ig&list=PLsYGHuNuBZcZIso_OSGv_CjaMQREMHpIA&index=1">see videos</a>).</li>
</ul>

## Setup
1. Bring up the VMs of Mininet and the SDN controller.
2. Clone this project to the Mininet VM and browse to the `iot-zipris` directory.
3. Bring up Mininet with the project's topology, OF 1.3 switches and the HPE VAN SDN Controller:

`sudo mn --custom exercises/iot_sec_host/infrastructure/iot-zipris-topo.py --topo ziprisTopo --controller=remote,ip=<SDN Controller IP> --switch ovsk,protocols=OpenFlow13`

<u>Note:</u> for simulating a realistic environment, post the following requests manually to the SDN controller:
1. Generate a token for the controller using the request in `exercises/iot_sec_host/infrastructure/payloads/request_auth.json`
2. Enable port-mirroring in the main router, so traffic from the home network will be mirrored to the 'security SmartNIC': `exercises/iot_sec_host/infrastructure/payloads/request_router_port_mirroring.json`
3. Enable DSCP marking on the home network switch: `exercises/iot_sec_host/infrastructure/payloads/request_switch_mark_iot_dscp.json` <b>or</b> `exercises/iot_sec_host/infrastructure/payloads/request_switch_mark_non-iot_dscp.json`

## Usage
The project's topology enables the following hosts:
1. `h1` - the security SmartNIC of the ISP
2. `h2` - an IoT device in the home network
3. `h4` - a non-IoT device in the home network
4. `h5` - a valid destination of `h2`
5. `h6` - an invalid destination of `h2`

After bringing up the project's Mininet topology, use `xterm <host name>` in order to control the hosts.<br />
On `h1`, browse `iot-zipris/exercises/iot_sec_host` and execute `python security_switch/listener.py h1` in order to monitor the traffic to `h1` and enable packets classification solution.<br />
On the rest of the hosts, browse `iot-zipris/exercises/iot_sec_host` and execute `python receive_qos.py <host name>` in order to monitor the traffic.<br />
Now use Mininet terminal in order to send traffic between the hosts and monitor the network's behavior.