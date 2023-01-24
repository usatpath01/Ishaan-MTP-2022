# 24 Jan

- Create a file `timer.py` which will intercept requests to and from docker containers running on current host and classify it as send and receive event. Also print from container, to container and timestamp.


- You can either do port based filtering (see activity only on ports which are exposed or containers are using to communicate), separately see connect and accept connections (following /usr/share/tools/bcc/tcpconnect and tcpaccept). Started implementing using this approach (timer_ports.py) but thought next approach is better.

- Find the namespace id (uint32) of overlay network and filter packets for that namespace (following /usr/share/tools/bcc/tcptracer)
  - [Step-1] Find the namespace id of network