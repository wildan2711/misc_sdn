from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib import mac

from ryu.app.wsgi import ControllerBase
from ryu.topology import event
from ryu.topology import switches
from collections import defaultdict

import random

# switches
switches = []

# mymac[srcmac]->(switch, port)
mymac = {}

# adjacency map [sw1][sw2]->port from sw1 to sw2
adjacency = defaultdict(lambda: defaultdict(lambda: None))


def minimum_distance(distance, Q):
    min = float('Inf')
    node = 0
    for v in Q:
        if distance[v] < min:
            min = distance[v]
            node = v
    return node


def get_path(src, dst, first_port, final_port):
    # Dijkstra's algorithm
    print "get_path is called, src=", src, " dst=", dst, " first_port=", first_port, " final_port=", final_port
    distance = {}
    previous = {}

    for dpid in switches:
        distance[dpid] = float('Inf')
        previous[dpid] = None

    distance[src] = 0
    Q = set(switches)
    print "Q=", Q

    while len(Q) > 0:
        u = minimum_distance(distance, Q)
        Q.remove(u)

        for p in switches:
            if adjacency[u][p] != None:
                # print p
                w = 1
                if distance[u] + w < distance[p]:
                    distance[p] = distance[u] + w
                    previous[p] = u

    r = []
    p = dst
    r.append(p)
    q = previous[p]
    while q is not None:
        if q == src:
            r.append(q)
            break
        p = q
        r.append(p)
        q = previous[p]

    r.reverse()
    if src == dst:
        path = [src]
    else:
        path = r

    # Now add the ports
    r = []
    in_port = first_port
    for s1, s2 in zip(path[:-1], path[1:]):
        out_port = adjacency[s1][s2]
        r.append((s1, in_port, out_port))
        in_port = adjacency[s2][s1]
    r.append((dst, in_port, final_port))
    return r


class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.server_index = 0
        self.server_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        self.virtual_ip = "10.0.0.20"
        self.virtual_mac = "dd:dd:dd:dd:dd:dd"
        self.arp_table = {}

    # Handy function that lists all attributes in the given object
    def ls(self, obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, instructions=inst)
        datapath.send_msg(mod)

    def install_path(self, ev, p, src_ip, dst_ip, mac_src, mac_dst):
        print "install_path is called"
        # print "p=", p, " src_mac=", src_mac, " dst_mac=", dst_mac
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for sw, in_port, out_port in p:
            print src_ip, "->", dst_ip, "via ", sw, " in_port=", in_port, " out_port=", out_port
            match_ip = parser.OFPMatch(
                in_port=in_port,
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip
            )
            match_arp = parser.OFPMatch(
                in_port=in_port,
                eth_type=ether_types.ETH_TYPE_ARP,
                arp_spa=src_ip,
                arp_tpa=dst_ip
            )
            actions = [parser.OFPActionOutput(out_port)]
            datapath = self.datapath_list[int(sw)]
            # self.add_flow(datapath, 1, match_eth, actions)
            self.add_flow(datapath, 1, match_ip, actions)
            self.add_flow(datapath, 1, match_arp, actions)

    def reply_arp(self, datapath, eth_dst, eth_src, dst_ip, src_ip, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(in_port)]
        ARP_Reply = packet.Packet()

        ARP_Reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=eth_dst,
            src=eth_src))
        ARP_Reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=eth_src,
            src_ip=src_ip,
            dst_mac=eth_dst,
            dst_ip=dst_ip))

        print ARP_Reply
        ARP_Reply.serialize()

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=ARP_Reply.data)
        datapath.send_msg(out)

    def load_balancing_handler(self, ev, eth, iphdr, in_port):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        # Round robin selection of servers
        total_servers = len(self.server_ips)

        index = self.server_index % total_servers
        selected_server_ip = self.server_ips[index]
        selected_server_mac = self.arp_table[selected_server_ip]
        selected_server_outport = self.mac_to_port[selected_server_mac]
        self.server_index += 1
        print("Selected server %s" % selected_server_ip)

        # Setup route to server
        match = ofp_parser.OFPMatch(in_port=in_port,
                                    eth_type=eth.ethertype,  eth_src=eth.src,    eth_dst=eth.dst,
                                    ip_proto=iphdr.proto,    ipv4_src=iphdr.src, ipv4_dst=iphdr.dst)

        actions = [ofp_parser.OFPActionSetField(eth_dst=selected_server_mac),
                   ofp_parser.OFPActionSetField(ipv4_dst=selected_server_ip),
                   ofp_parser.OFPActionOutput(selected_server_outport)]

        inst = [ofp_parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]

        cookie = random.randint(0, 0xffffffffffffffff)

        mod = ofp_parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=10,
                                    instructions=inst, buffer_id=msg.buffer_id, cookie=cookie)
        datapath.send_msg(mod)

        # Setup reverse route from server
        match = ofp_parser.OFPMatch(in_port=selected_server_outport,
                                    eth_type=eth.ethertype,  eth_src=selected_server_mac, eth_dst=eth.src,
                                    ip_proto=iphdr.proto,    ipv4_src=selected_server_ip, ipv4_dst=iphdr.src)

        actions = ([ofp_parser.OFPActionSetField(eth_src=self.virtual_mac),
                    ofp_parser.OFPActionSetField(ipv4_src=self.virtual_ip),
                    ofp_parser.OFPActionOutput(in_port)])

        inst = [ofp_parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]

        cookie = random.randint(0, 0xffffffffffffffff)

        mod = ofp_parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=10,
                                    instructions=inst, cookie=cookie)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)

        # avoid broadcast from LLDP
        if eth.ethertype == 35020:
            return

        if ipv6_pkt:  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if src not in mymac.keys():
            mymac[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if dst in mymac.keys():
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                    path = get_path(mymac[src][0], mymac[dst][0],
									mymac[src][1], mymac[dst][1])
                    reverse = get_path(mymac[dst][0], mymac[src][0],
									mymac[dst][1], mymac[src][1])
                    self.install_path(ev, path, src_ip, dst_ip, src, dst)
                    self.install_path(ev, reverse, dst_ip, src_ip, dst, src)
                    self.arp_table[src_ip] = src
                    self.arp_table[dst_ip] = dst
                    print self.arp_table
            elif dst == mac.BROADCAST_STR and dst_ip in self.arp_table:
                print "replying arp"
                mac_dst = self.arp_table[dst_ip]
                self.reply_arp(datapath, src, mac_dst, src_ip, dst_ip, in_port)

        actions = [parser.OFPActionOutput(out_port)]

        # print pkt
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def _switch_enter_handler(self, event):
        switch = event.switch.dp
        if switch.id not in switches:
            switches.append(switch.id)
            self.datapath_list[switch.id] = switch

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def _link_add_handler(self, event):
        s1 = event.link.src
        s2 = event.link.dst
        adjacency[s1.dpid][s2.dpid] = s1.port_no
        adjacency[s2.dpid][s1.dpid] = s2.port_no
