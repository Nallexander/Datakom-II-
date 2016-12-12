
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
LATENCY =1
RATE = 500000
ONOFFRATE = 300000
 


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
cmd.latency = LATENCY
cmd.rate = RATE
cmd.on_off_rate = ONOFFRATE
cmd.AddValue ("rate", "P2P data rate in bps")
cmd.AddValue ("latency", "P2P link Latency in miliseconds")
cmd.AddValue ("on_off_rate", "OnOffApplication data sending rate")
cmd.Parse(sys.argv)
print("Hej")
print(cmd.rate)
print(cmd.latency)
N0N1RATE  = RATE
N0N3RATE  = RATE
N1N2RATE  = RATE
N3N4RATE  = RATE
N3N5RATE  = RATE
N5N6RATE  = RATE
N3N7RATE  = RATE
N7N8RATE  = RATE
N7N9RATE  = RATE
N9N10RATE = RATE
N0N1LATENCY  = LATENCY
N0N3LATENCY  = LATENCY
N1N2LATENCY  = LATENCY
N3N4LATENCY  = LATENCY
N3N5LATENCY  = LATENCY
N5N6LATENCY  = LATENCY
N3N7LATENCY  = LATENCY
N7N8LATENCY  = LATENCY
N7N9LATENCY  = LATENCY
N9N10LATENCY = LATENCY


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

n0n3 = ns.network.NodeContainer()
n0n3.Add(nodes.Get(0))
n0n3.Add(nodes.Get(3))

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


# create point-to-point helper with common attributes

rateList = [N0N1RATE,N0N3RATE,N1N2RATE,N3N4RATE,N3N5RATE,N5N6RATE,N3N7RATE,N7N8RATE,N7N9RATE,N9N10RATE]
latencyList=[N0N1LATENCY,N0N3LATENCY,N1N2LATENCY,N3N4LATENCY,N3N5LATENCY,N5N6LATENCY,N3N7LATENCY,N7N8LATENCY,N7N9LATENCY,N9N10LATENCY]
pointToPointList = []
for num in range(10):
    pointToPoint = ns.point_to_point.PointToPointHelper()
    pointToPoint.SetDeviceAttribute("Mtu", ns.core.UintegerValue(1500))
    pointToPoint.SetDeviceAttribute("DataRate",
                            ns.network.DataRateValue(ns.network.DataRate(int(rateList[num]))))
    pointToPoint.SetChannelAttribute("Delay",
                            ns.core.TimeValue(ns.core.MilliSeconds(int(latencyList[num]))))
    pointToPointList.append(pointToPoint)
# install network devices for all nodes based on point-to-point links    
d0d1  = pointToPointList[0].Install(n0n1)
d0d3  = pointToPointList[1].Install(n0n3)
d1d2  = pointToPointList[2].Install(n1n2)
d3d4  = pointToPointList[3].Install(n3n4)
d3d5  = pointToPointList[4].Install(n3n5)
d5d6  = pointToPointList[5].Install(n5n6)
d3d7  = pointToPointList[6].Install(n3n7)
d7d8  = pointToPointList[7].Install(n7n8)
d7d9  = pointToPointList[8].Install(n7n9)
d9d10 = pointToPointList[9].Install(n9n10)

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
if0if3 = address.Assign(d0d3)

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
  sink_apps.Stop(ns.core.Seconds(50.0)) 

  # Create TCP connection from srcNode to dstNode 
  on_off_tcp_helper = ns.applications.OnOffHelper(socketFactory, 
                          ns.network.Address(ns.network.InetSocketAddress(dstAddr, 8080)))
  on_off_tcp_helper.SetAttribute("DataRate",
                      ns.network.DataRateValue(ns.network.DataRate(int(cmd.on_off_rate))))
  on_off_tcp_helper.SetAttribute("PacketSize", ns.core.UintegerValue(1500)) 
  on_off_tcp_helper.SetAttribute("OnTime",
                      ns.core.StringValue("ns3::ConstantRandomVariable[Constant=2]"))
  on_off_tcp_helper.SetAttribute("OffTime",
                        ns.core.StringValue("ns3::ConstantRandomVariable[Constant=1]"))
  #                      ns.core.StringValue("ns3::UniformRandomVariable[Min=1,Max=2]"))
  #                      ns.core.StringValue("ns3::ExponentialRandomVariable[Mean=2]"))

  # Install the client on node srcNode
  client_apps = on_off_tcp_helper.Install(srcNode)
  client_apps.Start(startTime)
  client_apps.Stop(stopTime)


SetupConnection(nodes.Get(2), nodes.Get(0), if0if1.GetAddress(0),
                   ns.core.Seconds(1.0), ns.core.Seconds(40.0), "TCP")
#SetupTcpConnection(nodes.Get(1), nodes.Get(3), if3if5.GetAddress(0),
#                   ns.core.Seconds(20.0), ns.core.Seconds(40.0))
#SetupConnection(nodes.Get(1), nodes.Get(3), if3if5.GetAddress(0),
#                   ns.core.Seconds(20.0), ns.core.Seconds(40.0), "UDP")


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
