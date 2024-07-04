# Identification and Management of "Elephants" in Ryu

## Project Description
This project was developed for the **"Software Defined Networking"** course at **Politecnico di Milano**. It aims to identify and manage high-traffic TCP connections, referred to as "elephants", in an SDN network using Ryu as the controller. A TCP connection is considered an elephant when its traffic volume exceeds a certain threshold. Short-lived connections are handled packet by packet, while for high-traffic connections, an OpenFlow rule is installed on the switch to route packets directly without involving the controller.

## Project Features
- Monitoring the traffic volume of TCP connections.
- Identifying connections that exceed a predefined traffic threshold.
- Installing OpenFlow rules on switches to route high-traffic connections without controller intervention.
- Proxy ARP for address resolution protocol management

## Prerequisites
- Python 3.6+
- Ryu SDN Framework
- NetworkX

## Configuration
Before starting the application, ensure to configure the parameters correctly in the `config.txt` file:
```txt
PACKET_THRESHOLD=2000  # Default threshold for the number of packets for an elephant
IDLE_TIMEOUT=30  # Connection inactivity timeout in seconds for inactivity connections
```
## Testing with Mininet
The controller was tested on a simulated network using Mininet. This allowed for preliminary testing and debugging in a controlled environment before deploying on a physical testbed.

To generate a ring topology in Mininet, use the following command:
```sh
sudo mn --topo ring,4 --controller=remote
```
This command creates a ring topology with 4 switches and sets up a remote controller.

The controller was also tested on more complex topologies to ensure robustness and performance in various network configurations.

To run the Ryu application:
```sh
ryu-manager controller.py
```

## Testbed
The project was deployed on a real network testbed to simulate a real network

### Functional Topology
#### Control Plane
- **SDN switches** connected through an **unmanaged switch** and a **WLAN mini-router**.
- **Mini-hosts** connected to the **SDN switches**.

Traffic was generated with iperf3 to simulate network loads.

## Documentation
For detailed information, please refer to the [testbed.pdf](testbed.pdf).
