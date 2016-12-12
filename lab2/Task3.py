
#
# This script simulates 6 nodes configured in a "dumb bell" network. See below:
#
# Network topology
#
#       n0 ---+      +--- n2
#             |      |
#             n4 -- n5
#             |      |
#       n1 ---+      +--- n3
#
# - All links are point-to-point with data rate 500kb/s and propagation delay 2ms
#
# Two data flows (and their applications are created):
# - A TCP flow form n0 to n2
# - A TCP flow from n1 to n3

#TCP time log: NS_LOG="*=prefix_time" python sim-tcp.py --latency=1

import sys
import ns.applications
import ns.core
import ns.internet
import ns.network
import ns.point_to_point
import ns.flow_monitor

# Debug flag
DEBUG = True


def print_debug(message):
    if(DEBUG):
        print(message)
    return()

#######################################################################################
# SEEDING THE RNG
#
# Enable this line to have random number being generated between runs.

#ns.core.RngSeedManager.SetSeed(int(time.time() * 1000 % (2**31-1)))


#######################################################################################
# LOGGING
#
# Here you may enable extra output logging. It will be printed to the stdout.
# This is mostly useful for debugging and investigating what is going on in the
# the simulator. You may use this output to generate your results as well, but
# you would have to write extra scripts for filtering and parsing the output.
# FlowMonitor may be a better choice of getting the information you want.


#ns.core.LogComponentEnable("UdpEchoClientApplication", ns.core.LOG_LEVEL_INFO)
#ns.core.LogComponentEnable("UdpEchoServerApplication", ns.core.LOG_LEVEL_INFO)
#ns.core.LogComponentEnable("PointToPointNetDevice", ns.core.LOG_LEVEL_ALL)
#ns.core.LogComponentEnable("DropTailQueue", ns.core.LOG_LEVEL_LOGIC)
#ns.core.LogComponentEnable("OnOffApplication", ns.core.LOG_LEVEL_INFO)
#ns.core.LogComponentEnable("TcpWestwood", ns.core.LOG_LEVEL_LOGIC)
#ns.core.LogComponentEnable("TcpTahoe", ns.core.LOG_LEVEL_LOGIC)
ns.core.LogComponentEnable("TcpCongestionOps", ns.core.LOG_LEVEL_INFO)





#######################################################################################
# COMMAND LINE PARSING
#
# Parse the command line arguments. Some simulation parameters can be set from the
# command line instead of in the script. You may start the simulation by:
#
# bash$ ./waf shell
# bash$ python sim-tcp.py --latency=10
#
# You can add your own parameters and there default values below. To access the values
# in the simulator, you use the variable cmd.something.

cmd = ns.core.CommandLine()

# Default values
cmd.latency = 1
cmd.rate = 5000000
cmd.on_off_rate = 50000000
cmd.AddValue ("rate", "P2P data rate in bps")
cmd.AddValue ("latency", "P2P link Latency in miliseconds")
#cmd.AddValue ("on_off_rate", "OnOffApplication data sending rate")
cmd.AddValue ("bulk_max_bytes", "BulkSendApplication data to be sent")
cmd.Parse(sys.argv)



#######################################################################################
# CREATE NODES

nodes = ns.network.NodeContainer()
nodes.Create(11)


#######################################################################################
# CONNECT NODES WITH POINT-TO-POINT CHANNEL
#
# We use a helper class to create the point-to-point channels. It helps us with creating
# the necessary objects on the two connected nodes as well, including creating the
# NetDevices (of type PointToPointNetDevice), etc.

# Set the default queue length to 5 packets (used by NetDevices)
# The first line is for older ns3 versions and the second for new versions.
#ns.core.Config.SetDefault("ns3::DropTailQueue::MaxPackets", ns.core.UintegerValue(5))
ns.core.Config.SetDefault("ns3::Queue::MaxPackets", ns.core.UintegerValue(5))


# To connect the point-to-point channels, we need to define NodeContainers for all the
# point-to-point channels.
n0n1 = ns.network.NodeContainer()
n0n1.Add(nodes.Get(0))
n0n1.Add(nodes.Get(1))

n1n3 = ns.network.NodeContainer()
n1n3.Add(nodes.Get(1))
n1n3.Add(nodes.Get(3))

n1n2 = ns.network.NodeContainer()
n1n2.Add(nodes.Get(1))
n1n2.Add(nodes.Get(2))

n3n4 = ns.network.NodeContainer()
n3n4.Add(nodes.Get(3))
n3n4.Add(nodes.Get(4))

n3n5 = ns.network.NodeContainer()
n3n5.Add(nodes.Get(3))
n3n5.Add(nodes.Get(5))

n5n6 = ns.network.NodeContainer()
n5n6.Add(nodes.Get(5))
n5n6.Add(nodes.Get(6))

n3n7 = ns.network.NodeContainer()
n3n7.Add(nodes.Get(3))
n3n7.Add(nodes.Get(7))

n7n8 = ns.network.NodeContainer()
n7n8.Add(nodes.Get(7))
n7n8.Add(nodes.Get(8))

n7n9 = ns.network.NodeContainer()
n7n9.Add(nodes.Get(7))
n7n9.Add(nodes.Get(9))

n9n10 = ns.network.NodeContainer()
n9n10.Add(nodes.Get(9))
n9n10.Add(nodes.Get(10))

pointToPoint = ns.point_to_point.PointToPointHelper()
def setRateLatency(nxnx, rate, latency):

    # create point-to-point helper with common attributes
    pointToPoint.SetDeviceAttribute("Mtu", ns.core.UintegerValue(1500))
    pointToPoint.SetDeviceAttribute("DataRate",
                                    ns.network.DataRateValue(ns.network.DataRate(int(rate))))
    pointToPoint.SetChannelAttribute("Delay",
                            ns.core.TimeValue(ns.core.MilliSeconds(int(latency))))
    return pointToPoint.Install(nxnx)

RATE = 100000000
LATENCY = 2
LOCALRATE = 2000000
LOCALLATENCY = 0
RRRATE = 500000000
RRLATENCY = 1
RCRATE = 100000000
RCLATENCY = 10


d0d1 = setRateLatency(n0n1, LOCALRATE, LOCALLATENCY)
d1d3 = setRateLatency(n1n3, 200000000, 10)
d1d2 = setRateLatency(n1n2, LOCALRATE, LOCALLATENCY)
d3d4 = setRateLatency(n3n4, RCRATE, RCLATENCY)
d3d5 = setRateLatency(n3n5, RRRATE, RRLATENCY)
d5d6 = setRateLatency(n5n6, RCRATE, RCLATENCY)
d3d7 = setRateLatency(n3n7, RRRATE, RRLATENCY)
d7d8 = setRateLatency(n7n8, RCRATE, RCLATENCY)
d7d9 = setRateLatency(n7n9, RRRATE, RRLATENCY)
d9d10 = setRateLatency(n9n10, RCRATE, RCLATENCY)


"""
# install network devices for all nodes based on point-to-point links
d0d1 = pointToPoint.Install(n0n1)
d0d3 = pointToPoint.Install(n0n3)
d1d2 = pointToPoint.Install(n1n2)
d3d4 = pointToPoint.Install(n3n4)
d3d5 = pointToPoint.Install(n3n5)
d5d6 = pointToPoint.Install(n5n6)
d3d7 = pointToPoint.Install(n3n7)
d7d8 = pointToPoint.Install(n7n8)
d7d9 = pointToPoint.Install(n7n9)
d9d10 = pointToPoint.Install(n9n10)
"""
# Here we can introduce an error model on the bottle-neck link (from node 4 to 5)
#em = ns.network.RateErrorModel()
#em.SetAttribute("ErrorUnit", ns.core.StringValue("ERROR_UNIT_PACKET"))
#em.SetAttribute("ErrorRate", ns.core.DoubleValue(0.02))
#d4d5.Get(1).SetReceiveErrorModel(em)


#######################################################################################
# CONFIGURE TCP
#
# Choose a TCP version and set some attributes.

# Set a TCP segment size (this should be inline with the channel MTU)
ns.core.Config.SetDefault("ns3::TcpSocket::SegmentSize", ns.core.UintegerValue(1448))

# If you want, you may set a default TCP version here. It will affect all TCP
# connections created in the simulator. If you want to simulate different TCP versions
# at the same time, see below for how to do that.
#ns.core.Config.SetDefault("ns3::TcpL4Protocol::SocketType",
#                          ns.core.StringValue("ns3::TcpTahoe"))
#                          ns.core.StringValue("ns3::TcpReno"))
#                          ns.core.StringValue("ns3::TcpNewReno"))
#                          ns.core.StringValue("ns3::TcpWestwood"))

# Some examples of attributes for some of the TCP versions.
#ns.core.Config.SetDefault("ns3::TcpNewReno::ReTxThreshold", ns.core.UintegerValue(4))
#ns.core.Config.SetDefault("ns3::TcpWestwood::ProtocolType",
#                          ns.core.StringValue("WestwoodPlus"))


#######################################################################################
# CREATE A PROTOCOL STACK
#
# This code creates an IPv4 protocol stack on all our nodes, including ARP, ICMP,
# pcap tracing, and routing if routing configurations are supplied. All links need
# different subnet addresses. Finally, we enable static routing, which is automatically
# setup by an oracle.

# Install networking stack for nodes
stack = ns.internet.InternetStackHelper()
stack.Install(nodes)

# Here, you may change the TCP version per node. A node can only support on version at
# a time, but different nodes can run different versions. The versions only affect the
# sending node. Note that this must called after stack.Install().
#
# The code below would tell node 0 to use TCP Tahoe and node 1 to use TCP Westwood.
#ns.core.Config.Set("/NodeList/0/$ns3::TcpL4Protocol/SocketType",
#                   ns.core.TypeIdValue(ns.core.TypeId.LookupByName ("ns3::TcpTahoe")))
#ns.core.Config.Set("/NodeList/1/$ns3::TcpL4Protocol/SocketType",
#                   ns.core.TypeIdValue(ns.core.TypeId.LookupByName ("ns3::TcpWestwood")))


# Assign IP addresses for net devices
address = ns.internet.Ipv4AddressHelper()


address.SetBase(ns.network.Ipv4Address("1.0.0.0"), ns.network.Ipv4Mask("255.255.255.0"))
if0if1 = address.Assign(d0d1)

address.SetBase(ns.network.Ipv4Address("1.1.0.0"), ns.network.Ipv4Mask("255.255.255.0"))
if1if2 = address.Assign(d1d2)

address.SetBase(ns.network.Ipv4Address("2.0.0.0"), ns.network.Ipv4Mask("255.255.255.0"))
if1if3 = address.Assign(d1d3)

address.SetBase(ns.network.Ipv4Address("2.1.0.0"), ns.network.Ipv4Mask("255.255.255.0"))
if3if4 = address.Assign(d3d4)

address.SetBase(ns.network.Ipv4Address("2.2.0.0"), ns.network.Ipv4Mask("255.255.255.0"))
if3if5 = address.Assign(d3d5)

address.SetBase(ns.network.Ipv4Address("2.2.1.0"), ns.network.Ipv4Mask("255.255.255.0"))
if5if6 = address.Assign(d5d6)

address.SetBase(ns.network.Ipv4Address("2.3.0.0"), ns.network.Ipv4Mask("255.255.255.0"))
if3if7 = address.Assign(d3d7)

address.SetBase(ns.network.Ipv4Address("2.3.1.0"), ns.network.Ipv4Mask("255.255.255.0"))
if7if8 = address.Assign(d7d8)

address.SetBase(ns.network.Ipv4Address("2.3.2.0"), ns.network.Ipv4Mask("255.255.255.0"))
if7if9 = address.Assign(d7d9)

address.SetBase(ns.network.Ipv4Address("2.3.3.0"), ns.network.Ipv4Mask("255.255.255.0"))
if9if10 = address.Assign(d9d10)


# Turn on global static routing so we can actually be routed across the network.
ns.internet.Ipv4GlobalRoutingHelper.PopulateRoutingTables()



#######################################################################################
# CREATE TCP APPLICATION AND CONNECTION
#
# Create a TCP client at node N0 and a TCP sink at node N2 using an On-Off application.
# An On-Off application alternates between on and off modes. In on mode, packets are
# generated according to DataRate, PacketSize. In off mode, no packets are transmitted.
# protocol = "UDP" / "TCP"  

def SetupConnection(srcNode, dstNode, dstAddr, startTime, stopTime, protocol):

  if (protocol == "UDP"):
    socketFactory = "ns3::UdpSocketFactory"
  else:
    socketFactory = "ns3::TcpSocketFactory"
  # Create a TCP sink at dstNode
  packet_sink_helper = ns.applications.PacketSinkHelper(socketFactory, 
                          ns.network.InetSocketAddress(ns.network.Ipv4Address.GetAny(), 
                                                       8080))
  sink_apps = packet_sink_helper.Install(dstNode)
  sink_apps.Start(ns.core.Seconds(1.0))
  sink_apps.Stop(ns.core.Seconds(61.0))

  # Create TCP connection from srcNode to dstNode
  #bulk_send_tcp_helper = ns.applications.BulkSendHelper(socketFactory, 
  #                        ns.network.Address(ns.network.InetSocketAddress(dstAddr, 8080)))
  #bulk_send_tcp_helper.SetAttribute("MaxBytes", ns.core.UintegerValue(int(cmd.bulk_max_bytes)))
  
  
  # Create TCP connection from srcNode to dstNode 
  on_off_tcp_helper = ns.applications.OnOffHelper(socketFactory, 
                          ns.network.Address(ns.network.InetSocketAddress(dstAddr, 8080)))
  on_off_tcp_helper.SetAttribute("DataRate",
                      ns.network.DataRateValue(ns.network.DataRate(int(cmd.on_off_rate))))
  on_off_tcp_helper.SetAttribute("PacketSize", ns.core.UintegerValue(1500)) 
  on_off_tcp_helper.SetAttribute("OnTime",
                         ns.core.StringValue("ns3::ConstantRandomVariable[Constant=1]"))
  on_off_tcp_helper.SetAttribute("OffTime",
                         ns.core.StringValue("ns3::ConstantRandomVariable[Constant=0]"))
  #                      ns.core.StringValue("ns3::UniformRandomVariable[Min=1,Max=2]"))
  #                      ns.core.StringValue("ns3::ExponentialRandomVariable[Mean=2]"))
  
  # Install the client on node srcNode
  client_apps = on_off_tcp_helper.Install(srcNode)
  client_apps.Start(startTime)
  client_apps.Stop(stopTime)


SetupConnection(nodes.Get(0), nodes.Get(2), if1if2.GetAddress(1),
                   ns.core.Seconds(1.0), ns.core.Seconds(31.0), "TCP")
SetupConnection(nodes.Get(0), nodes.Get(4), if3if4.GetAddress(1),
                   ns.core.Seconds(1.0), ns.core.Seconds(31.0), "TCP")
SetupConnection(nodes.Get(0), nodes.Get(6), if5if6.GetAddress(1),
                   ns.core.Seconds(1.0), ns.core.Seconds(31.0), "TCP")
SetupConnection(nodes.Get(0), nodes.Get(8), if7if8.GetAddress(1),
                   ns.core.Seconds(1.0), ns.core.Seconds(31.0), "TCP")
SetupConnection(nodes.Get(0), nodes.Get(10), if9if10.GetAddress(1),
                   ns.core.Seconds(1.0), ns.core.Seconds(31.0), "TCP")



#######################################################################################
# CREATE A PCAP PACKET TRACE FILE
#
# This line creates two trace files based on the pcap file format. It is a packet
# trace dump in a binary file format. You can use Wireshark to open these files and
# inspect every transmitted packets. Wireshark can also draw simple graphs based on
# these files.
#
# You will get two files, one for node 0 and one for node 1

pointToPoint.EnablePcap("d0d1", d0d1.Get(0), True)
#pointToPoint.EnablePcap("d1d4", d1d4.Get(0), True)
#pointToPoint.EnablePcap("d4d5", d4d5.Get(0), True)


#######################################################################################
# FLOW MONITOR
#
# Here is a better way of extracting information from the simulation. It is based on
# a class called FlowMonitor. This piece of code will enable monitoring all the flows
# created in the simulator. There are four flows in our example, one from the client to
# server and one from the server to the client for both TCP connections.

flowmon_helper = ns.flow_monitor.FlowMonitorHelper()
monitor = flowmon_helper.InstallAll()


#######################################################################################
# RUN THE SIMULATION
#
# We have to set stop time, otherwise the flowmonitor causes simulation to run forever

ns.core.Simulator.Stop(ns.core.Seconds(50.0))
ns.core.Simulator.Run()


#######################################################################################
# FLOW MONITOR ANALYSIS
#
# Simulation is finished. Let's extract the useful information from the FlowMonitor and
# print it on the screen.

# check for lost packets
monitor.CheckForLostPackets()

classifier = flowmon_helper.GetClassifier()

for flow_id, flow_stats in monitor.GetFlowStats():
  t = classifier.FindFlow(flow_id)
  proto = {6: 'TCP', 17: 'UDP'} [t.protocol]
  print ("FlowID: %i (%s %s/%s --> %s/%i)" % 
          (flow_id, proto, t.sourceAddress, t.sourcePort, t.destinationAddress, t.destinationPort))
          
  print ("  Tx Bytes: %i" % flow_stats.txBytes)
  print ("  Rx Bytes: %i" % flow_stats.rxBytes)
  print ("  Lost Pkt: %i" % flow_stats.lostPackets)
  print ("  Flow active: %fs - %fs" % (flow_stats.timeFirstTxPacket.GetSeconds(),
                                       flow_stats.timeLastRxPacket.GetSeconds()))
  print ("  Throughput: %f Mbps" % (flow_stats.rxBytes * 
                                     8.0 / 
                                     (flow_stats.timeLastRxPacket.GetSeconds() 
                                       - flow_stats.timeFirstTxPacket.GetSeconds())/
                                     1024/
                                     1024))


# This is what we want to do last
ns.core.Simulator.Destroy()
