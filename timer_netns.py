import docker
import yaml
import os


def get_netns_inode(pid):
    link = '/proc/' + str(pid) + '/ns/net'
    ret = os.readlink( link )
    ret = ret[ret.find("[")+1:ret.find("]")]
    return ret


def main():
    with open("input.yml") as f:
        containers_name = yaml.full_load(f)["local_containers"]
    overlay_networks = {}
    netns_ids = set()
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
            print(task["Name"], task["EndpointIP"], task["Info"]["Host IP"])

    
    
if __name__ == "__main__":
    main()