from bcc import BPF
import argparse
from bcc.utils import printb
from socket import inet_ntop, ntohs, AF_INET, SOCK_DGRAM, inet_ntoa
import socket
from struct import pack
import fcntl


def parse_args():
    usage = "python3 intercept_receive.py -P <destination_port_to_trace>"
    parser = argparse.ArgumentParser(
        description="Intercept incoming messages to container",
        formatter_class=argparse.RawDescriptionHelpFormatter, 
        epilog=usage)
    parser.add_argument("-P", "--port", required=True,
        help="destination ports to trace.")
    parser.add_argument("-I", "--interface",
        help="Name of host's primary interface. Eg: eno1, eth0")
    parser.add_argument("-H", "--host",
        help="IP address of host's primary interface. Eg: 10.12.6.5")
    parser.add_argument("-D", "--debug", action="store_true",
        help="Include this flag to print info that would help while debugging.")


    args = parser.parse_args()
    host_ip = ""
    interface = "eno1"
    if args.host:
        host_ip = args.host
    else:
        if args.interface:
            interface = args.interface
        def get_ip_address(ifname):
            s = socket.socket(AF_INET, SOCK_DGRAM)
            return inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                pack('256s', ifname)
            )[20:24])
        try:
            host_ip = get_ip_address(interface.encode('utf-8'))
        except OSError as e:
            print(f"Couldn't find IP address of interface: {interface}. Please confirm if such an interface exists.\nOSError: {e.strerror}")
            exit()


    def is_valid_ip(address):
        try:
            socket.inet_pton(socket.AF_INET, address)
        except AttributeError:  # no inet_pton here, sorry
            try:
                socket.inet_aton(address)
            except socket.error:
                return False
            return address.count('.') == 3
        except socket.error:  # not a valid address
            return False
        return True
    
    assert(is_valid_ip(host_ip))
    args.host = host_ip
    return args

def BPF_init(dport: int, debug=False):
    bpf_text = """
    #include <uapi/linux/ptrace.h>
    #include <net/sock.h>
    #include <bcc/proto.h>

    BPF_HASH(currsock, u32, struct sock *);

    struct ipv4_data_t {
        u64 ts_us;
        u32 pid;
        u32 uid;
        u32 saddr;
        u32 daddr;
        u64 ip;
        u16 lport;
        u16 dport;
        char task[TASK_COMM_LEN];
    };
    BPF_PERF_OUTPUT(ipv4_events);

    int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
    {
    
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = pid_tgid;

        // stash the sock ptr for lookup on return
        currsock.update(&tid, &sk);

        return 0;
    };

    static int trace_connect_return(struct pt_regs *ctx, short ipver)
    {
        int ret = PT_REGS_RC(ctx);
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = pid_tgid;

        struct sock **skpp;
        skpp = currsock.lookup(&tid);
        if (skpp == 0) {
            return 0;   // missed entry
        }

        if (ret != 0) {
            // failed to send SYNC packet, may not have populated
            // socket __sk_common.{skc_rcv_saddr, ...}
            currsock.delete(&tid);
            return 0;
        }

        // pull in details
        struct sock *skp = *skpp;
        u16 lport = skp->__sk_common.skc_num;
        u16 dport = skp->__sk_common.skc_dport;

        FILTER_PORT
        
        if (ipver != 4) { return 0; }
        
        struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
        data4.uid = bpf_get_current_uid_gid();
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        data4.lport = lport;
        data4.dport = ntohs(dport);
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
        
        currsock.delete(&tid);

        return 0;
    }

    int trace_connect_v4_return(struct pt_regs *ctx)
    {
        return trace_connect_return(ctx, 4);
    }
    """
    dports_if = 'dport != %d' % ntohs(dport)
    bpf_text = bpf_text.replace('FILTER_PORT',
            'if (%s) { currsock.delete(&tid); return 0; }' % dports_if)
    bpf_text = bpf_text.replace('FILTER_PORT', '')

    if debug:
        print("bpf_text:")
        print(bpf_text)
        print("-" * 50)

    # process event
    def handle_connect_event(cpu, data, size):
        event = b["ipv4_events"].event(data)
        global start_ts
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
        
        dest_ip = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
        
        printb(b"%-7d %-12.12s %-2d %-16s %-16s %-6d" % (event.pid,
            event.task, event.ip,
            inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
            dest_ip, event.dport))


    b = BPF(text=bpf_text)
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")

    print("Tracing connect ... Hit Ctrl-C to end")

    print("%-9s" % ("TIME(s)"), end="")
    print("%-7s %-12s %-2s %-16s %-16s %-6s" % ("PID", "COMM", "IP", "SADDR", "DADDR", "DPORT"))


    b["ipv4_events"].open_perf_buffer(handle_connect_event)

    return b

start_ts = 0

def main():
    args = parse_args()
    b = BPF_init(
        int(args.port),
        args.debug,
    )
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()


if __name__ == "__main__":
    main()