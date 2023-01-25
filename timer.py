import docker
import yaml
import os
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import hlcpy

TCP_EVENT_TYPE_CONNECT = 1
TCP_EVENT_TYPE_ACCEPT = 2

def get_netns_inode(pid):
    link = '/proc/' + str(pid) + '/ns/net'
    ret = os.readlink( link )
    ret = ret[ret.find("[")+1:ret.find("]")]
    return ret

class NetworkInfo:
    """
    
    """
    def __init__(self):
        self.overlay_networks = {}
        self.cont_ip_to_name = {}
        self.netns_ids = set()
        self.docker_ips = set()


def populate_network_info(net_info: NetworkInfo) -> None:
    with open("input.yml") as f:
        containers_name = yaml.full_load(f)["containers"]["local"]
    client = docker.APIClient(base_url='unix://var/run/docker.sock') 
    for cont in containers_name:
        try: 
            cont_inspect = client.inspect_container(cont)
        except docker.errors.NotFound:
            print(f"Container named {cont} is not found. Please make sure it's running!")
            exit()
        if not cont_inspect["State"]["Running"]:
            print(f"Container named {cont} is not running. Please make sure it's running!")
            exit()
        cont_pid = cont_inspect["State"]["Pid"]
        cont_networks = cont_inspect["NetworkSettings"]["Networks"]
        assert len(cont_networks) == 1, "This script is written for containers connected to exactly one ovelay network"
        net_name = list(cont_networks.keys())[0]
        net_info.overlay_networks[net_name] = cont_networks[net_name]["NetworkID"]
        net_info.netns_ids.add(get_netns_inode(cont_pid))
    for net_name, net_id in net_info.overlay_networks.items():
        net_inspect = client.inspect_network(net_name, verbose=True)
        for task in net_inspect["Services"][""]["Tasks"]:
            net_info.docker_ips.add(task["EndpointIP"])
            net_info.cont_ip_to_name[task["EndpointIP"]] = task["Name"]


def handle_send_event(from_cont: str, to_cont: str):
    # [TODO] send the current from_cont timestamp to timer of host in which to_cont resides. You can get host IP from docker network inspect -v <net> -> Services
    pass


def handle_receive_event(from_cont: str, to_cont: str):
    global timer
    print("Before updating:")
    print(timer.timestamps[to_cont])
    # [TODO] handle merge logic as in HLC paper. Current logic doesn't update logical component if physical component's not the same.
    # [TODO] handle receive events from other hosts
    timer.timestamps[to_cont].merge(timer.timestamps[from_cont])
    print("After updating:")
    print(timer.timestamps[to_cont])


def bpf_init(net_info: NetworkInfo) -> BPF:
    bpf_text = """
    #include <uapi/linux/ptrace.h>
    #include <net/sock.h>
    #include <net/inet_sock.h>
    #include <net/net_namespace.h>
    #include <bcc/proto.h>

    #define TCP_EVENT_TYPE_CONNECT 1
    #define TCP_EVENT_TYPE_ACCEPT  2

    struct tcp_ipv4_event_t {
        u64 ts_ns;
        u32 type;
        u32 pid;
        char comm[TASK_COMM_LEN];
        u8 ip;
        u32 saddr;
        u32 daddr;
        u16 sport;
        u16 dport;
        u32 netns;
    };
    BPF_PERF_OUTPUT(tcp_ipv4_event);

    // tcp_set_state doesn't run in the context of the process that initiated the
    // connection so we need to store a map TUPLE -> PID to send the right PID on
    // the event
    struct ipv4_tuple_t {
        u32 saddr;
        u32 daddr;
        u16 sport;
        u16 dport;
        u32 netns;
    };

    struct pid_comm_t {
        u64 pid;
        char comm[TASK_COMM_LEN];
    };

    BPF_HASH(tuplepid_ipv4, struct ipv4_tuple_t, struct pid_comm_t);
    BPF_HASH(connectsock, u64, struct sock *);

    static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct sock *skp)
    {
        u32 net_ns_inum = 0;
        u32 saddr = skp->__sk_common.skc_rcv_saddr;
        u32 daddr = skp->__sk_common.skc_daddr;
        struct inet_sock *sockp = (struct inet_sock *)skp;
        u16 sport = sockp->inet_sport;
        u16 dport = skp->__sk_common.skc_dport;
        #ifdef CONFIG_NET_NS
        net_ns_inum = skp->__sk_common.skc_net.net->ns.inum;
        #endif

        ##FILTER_NETNS##

        tuple->saddr = saddr;
        tuple->daddr = daddr;
        tuple->sport = sport;
        tuple->dport = dport;
        tuple->netns = net_ns_inum;

        // if addresses or ports are 0, ignore
        if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
            return 0;
        }

        return 1;
    }


    static bool check_family(struct sock *sk, u16 expected_family) 
    {
        u64 zero = 0;
        u16 family = sk->__sk_common.skc_family;
        return family == expected_family;
    }

    int trace_connect_v4_entry(struct pt_regs *ctx, struct sock *sk)
    {
        u64 pid = bpf_get_current_pid_tgid();
        
        u16 family = sk->__sk_common.skc_family;
        if (family != AF_INET) { return 0; }


        // stash the sock ptr for lookup on return
        connectsock.update(&pid, &sk);

        return 0;
    }

    int trace_connect_v4_return(struct pt_regs *ctx)
    {
        int ret = PT_REGS_RC(ctx);
        u64 pid = bpf_get_current_pid_tgid();

        struct sock **skpp;
        skpp = connectsock.lookup(&pid);
        if (skpp == 0) {
            return 0;       // missed entry
        }

        connectsock.delete(&pid);

        if (ret != 0) {
            // failed to send SYNC packet, may not have populated
            // socket __sk_common.{skc_rcv_saddr, ...}
            return 0;
        }

        // pull in details
        struct sock *skp = *skpp;
        struct ipv4_tuple_t t = { };
        if (!read_ipv4_tuple(&t, skp)) {
            return 0;
        }

        struct pid_comm_t p = { };
        p.pid = pid;
        bpf_get_current_comm(&p.comm, sizeof(p.comm));

        tuplepid_ipv4.update(&t, &p);

        return 0;
    }

    int trace_tcp_set_state_entry(struct pt_regs *ctx, struct sock *skp, int state)
    {
        if (state != TCP_ESTABLISHED && state != TCP_CLOSE) {
            return 0;
        }

        u16 family = skp->__sk_common.skc_family;
        if (family != AF_INET) { return 0; }
        
        u8 ipver = 0;
        if (check_family(skp, AF_INET)) {
            ipver = 4;
            struct ipv4_tuple_t t = { };
            if (!read_ipv4_tuple(&t, skp)) {
                return 0;
            }

            if (state == TCP_CLOSE) {
                tuplepid_ipv4.delete(&t);
                return 0;
            }

            struct pid_comm_t *p;
            p = tuplepid_ipv4.lookup(&t);
            if (p == 0) {
                return 0;       // missed entry
            }

            struct tcp_ipv4_event_t evt4 = { };
            evt4.ts_ns = bpf_ktime_get_ns();
            evt4.type = TCP_EVENT_TYPE_CONNECT;
            evt4.pid = p->pid >> 32;
            evt4.ip = ipver;
            evt4.saddr = t.saddr;
            evt4.daddr = t.daddr;
            evt4.sport = ntohs(t.sport);
            evt4.dport = ntohs(t.dport);
            evt4.netns = t.netns;

            int i;
            for (i = 0; i < TASK_COMM_LEN; i++) {
                evt4.comm[i] = p->comm[i];
            }

            tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
            tuplepid_ipv4.delete(&t);
        } 
        // else drop

        return 0;
    }


    int trace_accept_return(struct pt_regs *ctx)
    {


        struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
        u64 pid = bpf_get_current_pid_tgid();


        if (newsk == NULL) {
            return 0;
        }

        // pull in details
        u16 lport = 0, dport = 0;
        u32 net_ns_inum = 0;
        u8 ipver = 0;

        dport = newsk->__sk_common.skc_dport;
        lport = newsk->__sk_common.skc_num;

        // Get network namespace id, if kernel supports it
        #ifdef CONFIG_NET_NS
        net_ns_inum = newsk->__sk_common.skc_net.net->ns.inum;
        #endif

        ##FILTER_NETNS##
        
        u16 family = newsk->__sk_common.skc_family;
        if (family != AF_INET) { return 0; }

        if (check_family(newsk, AF_INET)) {
            ipver = 4;

            struct tcp_ipv4_event_t evt4 = { 0 };

            evt4.ts_ns = bpf_ktime_get_ns();
            evt4.type = TCP_EVENT_TYPE_ACCEPT;
            evt4.netns = net_ns_inum;
            evt4.pid = pid >> 32;
            evt4.ip = ipver;

            evt4.saddr = newsk->__sk_common.skc_rcv_saddr;
            evt4.daddr = newsk->__sk_common.skc_daddr;

            evt4.sport = lport;
            evt4.dport = ntohs(dport);
            bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));

            // do not send event if IP address is 0.0.0.0 or port is 0
            if (evt4.saddr != 0 && evt4.daddr != 0 &&
                evt4.sport != 0 && evt4.dport != 0) {
                tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
            }
        } 
        // else drop

        return 0;
    }
    """
    netns_if = ' && '.join(['net_ns_inum != %s' % id for id in net_info.netns_ids])
    netns_filter = 'if (%s) { return 0; }' % netns_if
    bpf_text = bpf_text.replace('##FILTER_NETNS##', netns_filter)

    # initialize BPF
    b = BPF(text=bpf_text)
    
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
    
    b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state_entry")
    b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_accept_return")

    def print_ipv4_event(cpu, data, size):
        # [TODO] Currently you are printing info about the message in this handler, if multiple such handlers are executing, output to stdout will be mangled. Make sure in the final timer implementation, the handlers will all be independent.
        event = b["tcp_ipv4_event"].event(data)

        # [TODO] can you filter this in ebpf itself?
        if event.type != 1 and event.type != 2:  
            return
        
        
        saddr = inet_ntop(AF_INET, pack("I", event.saddr))
        daddr = inet_ntop(AF_INET, pack("I", event.daddr))

        if saddr not in net_info.docker_ips or daddr not in net_info.docker_ips:
            return
            

        print("New message intercepted.")
        if event.type == TCP_EVENT_TYPE_CONNECT:
            print("Type: Send event")
            from_cont = saddr
            to_cont = daddr
            handle_send_event(net_info.cont_ip_to_name[from_cont], 
                net_info.cont_ip_to_name[to_cont])
        elif event.type == TCP_EVENT_TYPE_ACCEPT:
            print("Type: Receive event")
            from_cont = daddr
            to_cont = saddr
            handle_receive_event(net_info.cont_ip_to_name[from_cont], 
                net_info.cont_ip_to_name[to_cont])
        
        print(f"From: {net_info.cont_ip_to_name[from_cont]}")
        print(f"To {net_info.cont_ip_to_name[to_cont]}")
        print("-" * 35)

    b["tcp_ipv4_event"].open_perf_buffer(print_ipv4_event)
    return b


class Timer:
    # [TODO] should make the hlcpy implementation better using the original HLC paper: https://cse.buffalo.edu/tech-reports/2014-04.pdf
    timestamps = {}
    def __init__(self, containers=None):
        if containers:
            self.timestamps = {
                cont: hlcpy.HLC.from_now() 
                    for cont in containers
            }
    
timer = Timer()

def main():

    if os.geteuid() != 0:
        print("This script must be run as root\nBye!!")
        exit(1)

    # [TODO] import typing
    net_info = NetworkInfo()
    populate_network_info(net_info)
    all_container_names = list(net_info.cont_ip_to_name.values())
    global timer
    timer = Timer(all_container_names)

    b = bpf_init(net_info)
    
    all_conts_joined = ", ".join(all_container_names)
    print(f"\nMonitoring incoming and outgoing docker messages for the following containers: {all_conts_joined}\n")

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    # [TODO]  Handle two namespaces in same machine, call print_event only once 
    # [TODO]  Threading, lock, performance optimizations
    # [TODO]  How often do the docker IPs and netns_inode numbers change? Should you periodically refresh them? Also, containers will get added and removed from time to time, handle that.
    # [TODO]  Currently only IPv4 is supported, this code is referenced from /usr/share/tools/bcc/tcptracer. It's bpf_text has the same functions for IPv6 too, if you need them in future.
    # [TODO]  Add documentation, comments examplaining network namespace inode numbers, eBPF filtering on which kprobes, etc.
    # [TODO]  Handle edge cases, like container not up, etc.
    # [TODO]  Write tests

    main()