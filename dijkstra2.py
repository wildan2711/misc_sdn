from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import in_proto
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.lib import hub

from ryu.app.wsgi import ControllerBase
from ryu.topology import event
from ryu.topology import switches
from collections import defaultdict

import random
import itertools
import time

# switches
switches = []

# mymac[srcmac]->(switch, port)
mymac = {}

# adjacency map [sw1][sw2]->port from sw1 to sw2
adjacency = defaultdict(lambda: defaultdict(lambda: None))
delay = defaultdict(lambda: defaultdict(lambda: 0))

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
    print "get_path is called, src=%s dst=%s first_port=%s final_port=%s" % (
        src, dst, first_port, final_port)

    distance = defaultdict(lambda: float('Inf'))
    previous = defaultdict(lambda: None)

    distance[src] = 0
    Q = set(switches)

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
        self.servers = { # switch location of server ips
            1: "10.0.0.1",
            2: "10.0.0.3",
            5: "10.0.0.2"
        }
        self.server_index = 0
        self.virtual_ip = "10.0.0.20"
        self.virtual_mac = "dd:dd:dd:dd:dd:dd"
        self.controller_ip = "10.0.0.100"
        self.controller_mac = "dd:dd:dd:dd:dd:df"
        self.arp_table = {}
        
        # Random ethertype to evaluate latency
        self.PROBE_ETHERTYPE = 0x07C7

    # Handy function that lists all attributes in the given object
    def ls(self, obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))

    def network_monitor(self):
        ''' Monitors network RTT and Congestion '''

        self.logger.info('Starting monitoring sub-routine')
        while True:
            for s1, s2 in list(itertools.combinations(switches, 2)):
                switch = self.datapath_list[s1]
                peer_port = adjacency[s1][s2]
                actions = [switch.ofproto_parser.OFPActionOutput(peer_port)]

                pkt = packet.Packet()
                pkt.add_protocol(ethernet.ethernet(ethertype=self.PROBE_ETHERTYPE,
                                                   dst=0x000000000001,
                                                   src=0x000000000000))

                pkt.serialize()
                payload = '%d;%d;%f' % (s1, s2, time.time())
                data = pkt.data + payload

                out = switch.dp.ofproto_parser.OFPPacketOut(
                    datapath=switch.dp,
                    buffer_id=switch.dp.ofproto.OFP_NO_BUFFER,
                    data=data,
                    in_port=switch.dp.ofproto.OFPP_CONTROLLER,
                    actions=actions
                )

                switch.dp.send_msg(out)

            hub.sleep(1)

        self.logger.info('Stopping monitor')

    def probe_packet_handler(self, pkt):
        '''
        Handles a latency probe packets and computes the
        delay between two switches
        '''
        try:
            receive_time = time.time()
            # Ignoring 14 bytes of ethernet header
            data = pkt.data[14:].split(';')
            send_dpid = int(data[0])
            recv_dpid = int(data[1])
            inc_time = float(data[2])
            sample_delay = receive_time - inc_time
            delay[send_dpid][recv_dpid] = sample_delay
        except:
            self.logger.error('Unable to parse incoming probe packet')

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

        # Installing the flow rules to send latency probe packets
        match = parser.OFPMatch(eth_type=self.PROBE_ETHERTYPE)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 65000, match, actions)

        # server discovery
        if datapath.id in self.servers:
            dst = mac.BROADCAST_STR
            src = self.controller_mac
            dst_ip = self.servers[datapath.id]
            src_ip = self.controller_ip
            opcode = arp.ARP_REQUEST
            port = ofproto.OFPP_FLOOD
            self.send_arp(datapath, dst, src, dst_ip, src_ip, opcode, port)

        # Installing the flow rules to send latency probe packets
        match = parser.OFPMatch(eth_type=self.PROBE_ETHERTYPE)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 65000, match, actions)

    def install_path(self, ev, p, src_ip, dst_ip):
        print "install_path is called"
        # print "p=", p, " src_mac=", src_mac, " dst_mac=", dst_mac
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for sw, in_port, out_port in p:
            print src_ip, "->", dst_ip, "via ", sw, " out_port=", out_port
            match_ip = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip
            )
            match_arp = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_ARP,
                arp_spa=src_ip,
                arp_tpa=dst_ip
            )
            actions = [parser.OFPActionOutput(out_port)]
            datapath = self.datapath_list[int(sw)]
            self.add_flow(datapath, 1, match_ip, actions)
            self.add_flow(datapath, 1, match_arp, actions)

    def send_arp(self, datapath, eth_dst, eth_src, dst_ip, src_ip, opcode, port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port)]
        arp_packet = packet.Packet()

        arp_packet.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=eth_dst,
            src=eth_src))
        arp_packet.add_protocol(arp.arp(
            opcode=opcode,
            src_mac=eth_src,
            src_ip=src_ip,
            dst_mac=eth_dst,
            dst_ip=dst_ip))

        # print ARP_Reply
        arp_packet.serialize()

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=arp_packet.data)
        datapath.send_msg(out)

    # def server_selection()

    def load_balancing_handler(self, ev, eth, arp_pkt, in_port):
        '''
            Load balancing handler
            Installs a route to one of the available servers
            using dijkstra's algorithm costs for selection.
            Modifies the virtual address to the chosen server.
        '''
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        selected_server_ip = None
        minimum = float('Inf')
        path = []
        for switch in self.servers:
            ip_server = self.servers[switch]
            mac_server = self.arp_table[ip_server]
            p = get_path(mymac[eth.src][0], switch,
                         mymac[eth.src][1], mymac[mac_server][1])
            if len(p) < minimum:
                minimum = len(p)
                path = p
                selected_server_ip = self.servers[switch]

        print "Selected server %s" % selected_server_ip

        selected_server_mac = self.arp_table[selected_server_ip]
        selected_server_switch = path[-1][0]
        selected_server_inport = path[-1][1]
        selected_server_outport = path[-1][2]

        reversed_path = get_path(selected_server_switch, mymac[eth.src][0],
                                 mymac[selected_server_mac][1], mymac[eth.src][1])
        print path
        self.install_path(ev, path[:-1], arp_pkt.src_ip, self.virtual_ip)
        self.install_path(ev, reversed_path[1:], self.virtual_ip, arp_pkt.src_ip)

        # Setup route to server
        match_ip = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                       ipv4_src=arp_pkt.src_ip, ipv4_dst=self.virtual_ip)

        actions_ip = [ofp_parser.OFPActionSetField(eth_dst=selected_server_mac),
                      ofp_parser.OFPActionSetField(ipv4_dst=selected_server_ip),
                      ofp_parser.OFPActionOutput(selected_server_outport)]

        match_arp = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                        arp_spa=arp_pkt.src_ip, arp_tpa=self.virtual_ip)

        actions_arp = [ofp_parser.OFPActionSetField(eth_tha=selected_server_mac),
                       ofp_parser.OFPActionSetField(arp_tpa=selected_server_ip),
                       ofp_parser.OFPActionOutput(selected_server_outport)]

        inst_ip = [ofp_parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions_ip)]
        inst_arp = [ofp_parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions_arp)]


        cookie = random.randint(0, 0xffffffffffffffff)

        server_dp = self.datapath_list[selected_server_switch]
        mod_ip = ofp_parser.OFPFlowMod(datapath=server_dp, match=match_ip, idle_timeout=10,
                                       instructions=inst_ip, buffer_id=msg.buffer_id,
                                       cookie=cookie)
        mod_arp = ofp_parser.OFPFlowMod(datapath=server_dp, match=match_arp, idle_timeout=10,
                                        instructions=inst_arp, buffer_id=msg.buffer_id,
                                        cookie=cookie)
        server_dp.send_msg(mod_ip)
        server_dp.send_msg(mod_arp)

        # Setup reverse route from server
        match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    eth_src=selected_server_mac, eth_dst=eth.src,
                                    ipv4_src=selected_server_ip, ipv4_dst=arp_pkt.src_ip)
        
        actions = ([ofp_parser.OFPActionSetField(eth_src=self.virtual_mac),
                    ofp_parser.OFPActionSetField(ipv4_src=self.virtual_ip),
                    ofp_parser.OFPActionOutput(selected_server_inport)])
        
        inst = [ofp_parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        
        cookie = random.randint(0, 0xffffffffffffffff)

        mod = ofp_parser.OFPFlowMod(datapath=server_dp, match=match, idle_timeout=10,
                                       instructions=inst, cookie=cookie)
        server_dp.send_msg(mod)

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

        if eth.ethertype == self.PROBE_ETHERTYPE:
            self.probe_packer_handler()

        if ipv6_pkt:  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            self.add_flow(datapath, 1, match, [])
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        if src not in mymac.keys():
            mymac[src] = (dpid, in_port)
            self.mac_to_port[dpid][src] = in_port

        out_port = ofproto.OFPP_FLOOD

        if arp_pkt:
            print pkt
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REPLY:
                if dst == self.controller_mac:
                    self.arp_table[src_ip] = src
                    match_controller = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_ARP,
                        arp_op=arp.ARP_REQUEST,
                        arp_sha=self.controller_mac
                    )
                    self.add_flow(datapath, 2, match_controller, [])
                    return
                elif dst_ip in self.servers.values():
                    return
                elif dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                    path = get_path(mymac[src][0], mymac[dst][0], mymac[src][1], mymac[dst][1])
                    reverse = get_path(mymac[dst][0], mymac[src][0], mymac[dst][1], mymac[src][1])
                    self.install_path(ev, path, src_ip, dst_ip)
                    self.install_path(ev, reverse, dst_ip, src_ip)
                    self.arp_table[src_ip] = src
                    self.arp_table[dst_ip] = dst
            elif dst_ip == self.virtual_ip:
                self.load_balancing_handler(ev, eth, arp_pkt, in_port)
                # Reply ARP
                opcode = arp.ARP_REPLY
                reply_mac = self.virtual_mac
                self.send_arp(datapath, src, reply_mac, src_ip, dst_ip, opcode, in_port)

        actions = [parser.OFPActionOutput(out_port)]

        # print pkt
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 2, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def _switch_enter_handler(self, ev):
        switch = ev.switch.dp
        if switch.id not in switches:
            switches.append(switch.id)
            self.datapath_list[switch.id] = switch

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def _link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        adjacency[s1.dpid][s2.dpid] = s1.port_no
        adjacency[s2.dpid][s1.dpid] = s2.port_no
