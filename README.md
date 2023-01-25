# Timer implementation using HLC

## Setup instructions:

- You need access to two Linux hosts for initial setup.
- Install [eBPF](https://github.com/iovisor/bcc/blob/master/INSTALL.md). Prefer installation from source for your distro, sometimes package installation (sudo apt install <package>) doesn't work because of version conflicts. This will install bcc library and python-bcc. 
- Install [docker](https://docs.docker.com/engine/install/ubuntu/) CLI. Make sure to run [post-installation steps](https://docs.docker.com/engine/install/linux-postinstall/) to avoid typing sudo for each docker command and for starting docker on boot.


### Run docker apps

We'll initialize a docker swarm with Host1 as the manager, join the swarm from Host2 as a worker, create an [overlay network](https://docs.docker.com/network/network-tutorial-overlay/#use-an-overlay-network-for-standalone-containers) on this swarm and run 1 docker app on Host1 and 2 apps on Host2. Follow the order in which the steps are listed, commands have to be run back and forth between the two hosts.

---
#### Needs to be done once
**Host1**
1. `docker swarm init`
3. `docker network create --driver=overlay --attachable flask_net_overlay`


**Host2**
1. 
`docker swarm join --token SWMTKN-1-5g90q48weqrtqryq4kj6ow0e8xm9wmv9o6vgqc5j320ymybd5c-8ex8j0bc40s6hgvy5ui5gl4gy 172.31.47.252:2377`


---
#### Needs to be done frequently
**Host1**
1. `cd docker_apps/host1_app1`
2. `./launch.sh`
3. `cd ../host1_app2`
4. `./launch.sh`


**Host2**
1. `cd docker_apps/host2_app1`
2. `./launch.sh`

Note: You will join swarm from an IP address (ethernet interface of Wifi), if your IP changes, networking between hosts won't work.

### Frequently used docker commands

- `docker network ls`
- `docker network inspect -v <net_name_or_id>`
- `docker node ls`
- `docker inspect <container_name_or_id>`
- `docker build`, `docker run`, `docker stop`, `docker rm`
- `docker ps -a`

### Run the timer

**About timer.py**
- You can either do port based filtering (see activity only on ports which are exposed or containers are using to communicate), separately trace connect and accept connections (following /usr/share/tools/bcc/tcpconnect and tcpaccept). Started implementing using this approach (ports_timer.py) but thought netns_inode_num approach is better.
- Find the namespace id (as in uint32 link visible on `ls -l /proc/{$container_PID}/ns/net`) of containers on this overlay network and filter packets for those namespaces (following /usr/share/tools/bcc/tcptracer)
---
- Install python dependencies (docker, pyyaml, iso8601, etc.) required to run timer.py and hlcpy manually.
- List the containers running locally that you wish to trace in input.yml
- `sudo python3 timer.py`

### TODO in current timer implementation

1. [TODO]  Handle two namespaces in same machine, call print_event only once 
2. [TODO]  Threading, lock, performance optimizations
3. [TODO]  How often do the docker IPs and netns_inode numbers change? Should you periodically refresh them? Also, containers will get added and removed from time to time, handle that.
4. [TODO]  Currently only IPv4 is supported, this code is referenced from /usr/share/tools/bcc/tcptracer. It's bpf_text has the same functions for IPv6 too, if you need them in future.
5. [TODO]  Add documentation, comments examplaining network namespace inode numbers, eBPF filtering on which kprobes, etc.
6. [TODO]  Handle edge cases, like container not up, etc.
7. [TODO]  Write tests
8. [TODO]  def handle_send_event: send the current from_cont timestamp to timer of host in which to_cont resides. You can get host IP from docker network inspect -v <net> -> Services
9. def handle_receive_event: [TODO] handle merge logic as in HLC paper. Current logic doesn't update logical component if physical component's not the same.
10. def handle_receive_event:  [TODO] handle receive events from other hosts
11. def print_ipv4_event:  [TODO] Currently you are printing info about the message in this handler, if multiple such handlers are executing, output to stdout will be mangled. Make sure in the final timer implementation, the handlers will all be independent.
12. def print_ipv4_event:  [TODO] can you filter this in ebpf itself?
13. [TODO] should make the hlcpy implementation better using the original HLC paper: https://cse.buffalo.edu/tech-reports/2014-04.pdf
14. [TODO] import typing; Properly annotate code using type checking


### Next steps 


- make it run with real world docker-compose that has services, etc. Make it plug and play.
  - You may also after discussion make it work with OpenWhisk, Kubernetes, etc.
- Create a timer daemon service registered with systemd.
- create an application running on multiple hosts, force their system clocks to drift, use your timer and create a CFG to show that the generated order is correct. You will need to interact with writer service (Rajat).