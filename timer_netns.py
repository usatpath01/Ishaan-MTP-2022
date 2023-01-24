import docker
import yaml
import os
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

def get_netns_inode(pid):
    link = '/proc/' + str(pid) + '/ns/net'
    ret = os.readlink( link )
    ret = ret[ret.find("[")+1:ret.find("]")]
    return ret




start_ts = 0

def main():
    with open("input.yml") as f:
        containers_name = yaml.full_load(f)["local_containers"]
    overlay_networks = {}
    netns_ids = set()
    docker_ips = set()
    client = docker.APIClient(base_url='unix://var/run/docker.sock') 
    for cont in containers_name:
        cont_inspect = client.inspect_container(cont)
        cont_pid = cont_inspect["State"]["Pid"]
        cont_networks = cont_inspect["NetworkSettings"]["Networks"]
        assert len(cont_networks) == 1, "this script is written for containers connected to exactly one ovelay network"
        net_name = list(cont_networks.keys())[0]
        overlay_networks[net_name] = cont_networks[net_name]["NetworkID"]
        netns_ids.add(get_netns_inode(cont_pid))
        # print("%-15s, %-5s, %-15s" % (cont, container_pid, get_netns_inode(container_pid)))
    print(netns_ids)
    for net_name, net_id in overlay_networks.items():
        net_inspect = client.inspect_network(net_name, verbose=True)
        for task in net_inspect["Services"][""]["Tasks"]:
            docker_ips.add(task["EndpointIP"])
            print(task["Name"], task["EndpointIP"], task["Info"]["Host IP"])
    
    def print_ipv4_event(cpu, data, size):
        event = b["tcp_ipv4_event"].event(data)

        # [TODO] can you filter this in ebpf itself?
        if event.type != 1 and event.type != 2:  
            return
        if event.type == 1:
            type_str = "C"
        elif event.type == 2:
            type_str = "A"
        
        saddr = inet_ntop(AF_INET, pack("I", event.saddr))
        daddr = inet_ntop(AF_INET, pack("I", event.daddr))

        if saddr not in docker_ips or daddr not in docker_ips:
            return
        print("%-2s " % (type_str), end="")

        print("%-6d %-16s %-2d %-16s %-16s %-6d %-6d" %
            (event.pid, event.comm.decode('utf-8', 'replace'),
            event.ip,
            saddr,
            daddr,
            event.sport,
            event.dport), end="")
        print()
            
    netns_if = ' && '.join(['net_ns_inum != %s' % id for id in netns_ids])
    netns_filter = 'if (%s) { return 0; }' % netns_if

    bpf_text = """
    #include <uapi/linux/ptrace.h>
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wtautological-compare"
    #include <net/sock.h>
    #pragma clang diagnostic pop
    #include <net/inet_sock.h>
    #include <net/net_namespace.h>
    #include <bcc/proto.h>

    #define TCP_EVENT_TYPE_CONNECT 1
    #define TCP_EVENT_TYPE_ACCEPT  2
    #define TCP_EVENT_TYPE_CLOSE   3

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

    struct tcp_ipv6_event_t {
        u64 ts_ns;
        u32 type;
        u32 pid;
        char comm[TASK_COMM_LEN];
        unsigned __int128 saddr;
        unsigned __int128 daddr;
        u16 sport;
        u16 dport;
        u32 netns;
        u8 ip;
    };
    BPF_PERF_OUTPUT(tcp_ipv6_event);

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

    struct ipv6_tuple_t {
        unsigned __int128 saddr;
        unsigned __int128 daddr;
        u16 sport;
        u16 dport;
        u32 netns;
    };

    struct pid_comm_t {
        u64 pid;
        char comm[TASK_COMM_LEN];
    };

    BPF_HASH(tuplepid_ipv4, struct ipv4_tuple_t, struct pid_comm_t);
    BPF_HASH(tuplepid_ipv6, struct ipv6_tuple_t, struct pid_comm_t);

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

    static int read_ipv6_tuple(struct ipv6_tuple_t *tuple, struct sock *skp)
    {
    u32 net_ns_inum = 0;
    unsigned __int128 saddr = 0, daddr = 0;
    struct inet_sock *sockp = (struct inet_sock *)skp;
    u16 sport = sockp->inet_sport;
    u16 dport = skp->__sk_common.skc_dport;
    #ifdef CONFIG_NET_NS
    net_ns_inum = skp->__sk_common.skc_net.net->ns.inum;
    #endif
    bpf_probe_read_kernel(&saddr, sizeof(saddr),
                    skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&daddr, sizeof(daddr),
                    skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

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

    static bool check_family(struct sock *sk, u16 expected_family) {
    u64 zero = 0;
    u16 family = sk->__sk_common.skc_family;
    return family == expected_family;
    }

    int trace_connect_v4_entry(struct pt_regs *ctx, struct sock *sk)
    {


    u64 pid = bpf_get_current_pid_tgid();

    ##FILTER_PID##
    
    u16 family = sk->__sk_common.skc_family;
    ##FILTER_FAMILY##


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

    int trace_connect_v6_entry(struct pt_regs *ctx, struct sock *sk)
    {

    u64 pid = bpf_get_current_pid_tgid();

    ##FILTER_PID##
    u16 family = sk->__sk_common.skc_family;
    ##FILTER_FAMILY##

    // stash the sock ptr for lookup on return
    connectsock.update(&pid, &sk);

    return 0;
    }

    int trace_connect_v6_return(struct pt_regs *ctx)
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
    struct ipv6_tuple_t t = { };
    if (!read_ipv6_tuple(&t, skp)) {
        return 0;
    }

    struct pid_comm_t p = { };
    p.pid = pid;
    bpf_get_current_comm(&p.comm, sizeof(p.comm));

    tuplepid_ipv6.update(&t, &p);

    return 0;
    }

    int trace_tcp_set_state_entry(struct pt_regs *ctx, struct sock *skp, int state)
    {
    if (state != TCP_ESTABLISHED && state != TCP_CLOSE) {
        return 0;
    }

    u16 family = skp->__sk_common.skc_family;
    ##FILTER_FAMILY##
    
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
    } else if (check_family(skp, AF_INET6)) {
        ipver = 6;
        struct ipv6_tuple_t t = { };
        if (!read_ipv6_tuple(&t, skp)) {
            return 0;
        }

        if (state == TCP_CLOSE) {
            tuplepid_ipv6.delete(&t);
            return 0;
        }

        struct pid_comm_t *p;
        p = tuplepid_ipv6.lookup(&t);
        if (p == 0) {
            return 0;       // missed entry
        }

        struct tcp_ipv6_event_t evt6 = { };
        evt6.ts_ns = bpf_ktime_get_ns();
        evt6.type = TCP_EVENT_TYPE_CONNECT;
        evt6.pid = p->pid >> 32;
        evt6.ip = ipver;
        evt6.saddr = t.saddr;
        evt6.daddr = t.daddr;
        evt6.sport = ntohs(t.sport);
        evt6.dport = ntohs(t.dport);
        evt6.netns = t.netns;

        int i;
        for (i = 0; i < TASK_COMM_LEN; i++) {
            evt6.comm[i] = p->comm[i];
        }

        tcp_ipv6_event.perf_submit(ctx, &evt6, sizeof(evt6));
        tuplepid_ipv6.delete(&t);
    }
    // else drop

    return 0;
    }

    int trace_close_entry(struct pt_regs *ctx, struct sock *skp)
    {


    u64 pid = bpf_get_current_pid_tgid();

    ##FILTER_PID##
    
    u16 family = skp->__sk_common.skc_family;
    ##FILTER_FAMILY##

    u8 oldstate = skp->sk_state;
    // Don't generate close events for connections that were never
    // established in the first place.
    if (oldstate == TCP_SYN_SENT ||
        oldstate == TCP_SYN_RECV ||
        oldstate == TCP_NEW_SYN_RECV)
        return 0;

    u8 ipver = 0;
    if (check_family(skp, AF_INET)) {
        ipver = 4;
        struct ipv4_tuple_t t = { };
        if (!read_ipv4_tuple(&t, skp)) {
            return 0;
        }

        struct tcp_ipv4_event_t evt4 = { };
        evt4.ts_ns = bpf_ktime_get_ns();
        evt4.type = TCP_EVENT_TYPE_CLOSE;
        evt4.pid = pid >> 32;
        evt4.ip = ipver;
        evt4.saddr = t.saddr;
        evt4.daddr = t.daddr;
        evt4.sport = ntohs(t.sport);
        evt4.dport = ntohs(t.dport);
        evt4.netns = t.netns;
        bpf_get_current_comm(&evt4.comm, sizeof(evt4.comm));

        tcp_ipv4_event.perf_submit(ctx, &evt4, sizeof(evt4));
    } else if (check_family(skp, AF_INET6)) {
        ipver = 6;
        struct ipv6_tuple_t t = { };
        if (!read_ipv6_tuple(&t, skp)) {
            return 0;
        }

        struct tcp_ipv6_event_t evt6 = { };
        evt6.ts_ns = bpf_ktime_get_ns();
        evt6.type = TCP_EVENT_TYPE_CLOSE;
        evt6.pid = pid >> 32;
        evt6.ip = ipver;
        evt6.saddr = t.saddr;
        evt6.daddr = t.daddr;
        evt6.sport = ntohs(t.sport);
        evt6.dport = ntohs(t.dport);
        evt6.netns = t.netns;
        bpf_get_current_comm(&evt6.comm, sizeof(evt6.comm));

        tcp_ipv6_event.perf_submit(ctx, &evt6, sizeof(evt6));
    }
    // else drop

    return 0;
    };

    int trace_accept_return(struct pt_regs *ctx)
    {


    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    u64 pid = bpf_get_current_pid_tgid();

    ##FILTER_PID##

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
    ##FILTER_FAMILY##

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
    } else if (check_family(newsk, AF_INET6)) {
        ipver = 6;

        struct tcp_ipv6_event_t evt6 = { 0 };

        evt6.ts_ns = bpf_ktime_get_ns();
        evt6.type = TCP_EVENT_TYPE_ACCEPT;
        evt6.netns = net_ns_inum;
        evt6.pid = pid >> 32;
        evt6.ip = ipver;

        bpf_probe_read_kernel(&evt6.saddr, sizeof(evt6.saddr),
                        newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&evt6.daddr, sizeof(evt6.daddr),
                        newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

        evt6.sport = lport;
        evt6.dport = ntohs(dport);
        bpf_get_current_comm(&evt6.comm, sizeof(evt6.comm));

        // do not send event if IP address is 0.0.0.0 or port is 0
        if (evt6.saddr != 0 && evt6.daddr != 0 &&
            evt6.sport != 0 && evt6.dport != 0) {
            tcp_ipv6_event.perf_submit(ctx, &evt6, sizeof(evt6));
        }
    }
    // else drop

    return 0;
    }
    """
    bpf_text = bpf_text.replace('##FILTER_FAMILY##',
            'if (family != AF_INET) { return 0; }')
    bpf_text = bpf_text.replace('##FILTER_PID##', "")
    bpf_text = bpf_text.replace('##FILTER_NETNS##', netns_filter)

    # initialize BPF
    b = BPF(text=bpf_text)
    
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
    
    b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state_entry")
    b.attach_kprobe(event="tcp_close", fn_name="trace_close_entry")
    b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_accept_return")

    print("Tracing TCP established connections. Ctrl-C to end.")

    
    
    print("%-2s %-6s %-16s %-2s %-16s %-16s %-6s %-6s" %
            ("T", "PID", "COMM", "IP", "SADDR", "DADDR", "SPORT", "DPORT"))
                                                                                                                

    b["tcp_ipv4_event"].open_perf_buffer(print_ipv4_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    print("[TODO]  What's  if (container_should_be_filtered()) ")
    print("[TODO]  Handle two namespaces in same machine, call only once ")
    main()