# Import additional necessary modules
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
from pox.lib.packet.arp import arp
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
import time

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overridden on the command line.
_flood_delay = 0

class LearningSwitch (object):
    """
    The learning switch "brain" associated with a single OpenFlow switch.
    """

    def __init__ (self, connection, transparent):
        # Switch we'll be adding L2 learning switch capabilities to
        self.connection = connection
        self.transparent = transparent

        # Our table
        self.macToPort = {}

        # We want to hear PacketIn messages, so we listen
        # to the connection
        connection.addListeners(self)

        # We just use this to know when to log a helpful message
        self.hold_down_expired = _flood_delay == 0

        log.info("LearningSwitch initialized for %s", dpid_to_str(connection.dpid))

    def _handle_PacketIn (self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """

        packet = event.parsed

        def flood (message = None):
            """ Floods the packet """
            msg = of.ofp_packet_out()
            if time.time() - self.connection.connect_time >= _flood_delay:
                if self.hold_down_expired is False:
                    self.hold_down_expired = True
                    log.info("%s: Flood hold-down expired -- flooding", dpid_to_str(event.dpid))
                if message is not None: log.debug(message)
                msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            else:
                log.info("Holding down flood for %s", dpid_to_str(event.dpid))
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)

        def drop (duration = None):
            """
            Drops this packet and optionally installs a flow to continue
            dropping similar ones for a while
            """
            if duration is not None:
                if not isinstance(duration, tuple):
                    duration = (duration,duration)
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet)
                msg.idle_timeout = duration[0]
                msg.hard_timeout = duration[1]
                msg.buffer_id = event.ofp.buffer_id
                self.connection.send(msg)
            elif event.ofp.buffer_id is not None:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                self.connection.send(msg)

        self.macToPort[packet.src] = event.port  # 1

        if not self.transparent:  # 2
            if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
                drop()  # 2a
                return

        if packet.find('arp'):
            log.info("Handling ARP packet from %s to %s", packet.src, packet.dst)
            if packet.payload.opcode == arp.REQUEST:
                log.info("Received ARP REQUEST from %s", packet.src)
            elif packet.payload.opcode == arp.REPLY:
                log.info("Received ARP REPLY from %s", packet.src)

        if packet.find('ipv4') and packet.find('icmp'):
            # Block ICMP traffic between h1 and h2
            ipv4_packet = packet.find('ipv4')
            if ipv4_packet.srcip == "10.0.0.1" and ipv4_packet.dstip == "10.0.0.2":
                log.info("Blocking ICMP traffic between 10.0.0.1 and 10.0.0.2")
                drop()
                return

        if packet.dst.is_multicast:
            flood("Flooding multicast packet from %s" % (packet.src,))  # 3a
        else:
            if packet.dst not in self.macToPort:  # 4
                flood("Port for %s unknown -- flooding" % (packet.dst,))  # 4a
            else:
                port = self.macToPort[packet.dst]
                if port == event.port:  # 5
                    log.warning("Same port for packet from %s -> %s on %s.%s. Drop.",
                        packet.src, packet.dst, dpid_to_str(event.dpid), port)
                    drop(10)
                    return

                # 6 - Install flow table entry
                log.debug("Installing flow for %s.%i -> %s.%i", packet.src, event.port, packet.dst, port)
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet, event.port)
                msg.idle_timeout = 10
                msg.hard_timeout = 30
                msg.actions.append(of.ofp_action_output(port = port))
                msg.data = event.ofp  # 6a
                self.connection.send(msg)


class l2_learning (object):
    """
    Waits for OpenFlow switches to connect and makes them learning switches.
    """
    def __init__ (self, transparent, ignore = None):
        """
        Initialize

        See LearningSwitch for meaning of 'transparent'
        'ignore' is an optional list/set of DPIDs to ignore
        """
        core.openflow.addListeners(self)
        self.transparent = transparent
        self.ignore = set(ignore) if ignore else ()

    def _handle_ConnectionUp (self, event):
        if event.dpid in self.ignore:
            log.debug("Ignoring connection %s", event.connection)
            return
        log.info("Connection %s", event.connection)
        LearningSwitch(event.connection, self.transparent)


def launch (transparent=False, hold_down=_flood_delay, ignore = None):
    """
    Starts an L2 learning switch.
    """
    try:
        global _flood_delay
        _flood_delay = int(str(hold_down), 10)
        assert _flood_delay >= 0
    except:
        raise RuntimeError("Expected hold-down to be a number")

    if ignore:
        ignore = ignore.replace(',', ' ').split()
        ignore = set(str_to_dpid(dpid) for dpid in ignore)

    core.registerNew(l2_learning, str_to_bool(transparent), ignore)
