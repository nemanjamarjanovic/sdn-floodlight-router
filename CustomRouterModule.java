package net.floodlightcontroller.customrouter;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.OFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.NodePortTuple;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetDlDst;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author nemanja.marjanovic
 *
 */
public class CustomRouterModule implements IOFMessageListener,
		IFloodlightModule {

	protected static Logger logger;
	protected IFloodlightProviderService floodlightProvider;
	protected ILinkDiscoveryService linkDiscoveryProvider;
	protected IDeviceService deviceProvider;
	protected IOFSwitchService switchProvider;
	protected IRoutingService routingProvider;

	private Map<DatapathId, CustomRouter> routers = new HashMap<DatapathId, CustomRouter>();
	private Map<DatapathId, Map<MacAddress, OFPort>> switches = new HashMap<DatapathId, Map<MacAddress, OFPort>>();
	private Map<Ethernet, DatapathId> ethernetHistory = new HashMap<Ethernet, DatapathId>();
	private Map<IPv4, DatapathId> ipHistory = new HashMap<IPv4, DatapathId>();

	protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 60; // in seconds
	protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
	protected static short FLOWMOD_PRIORITY = 100;

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		CustomRouter currentRouter = null;

		Ethernet ethernet = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		if (ethernetHistory.containsKey(ethernet)
				&& ethernetHistory.get(ethernet).equals(sw.getId())) {
			return Command.STOP;
		}
		ethernetHistory.put(ethernet, sw.getId());

		OFPacketIn pi = (OFPacketIn) msg;
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi
				.getInPort() : pi.getMatch().get(MatchField.IN_PORT));

		if (routers.containsKey(sw.getId())) {
			currentRouter = routers.get(sw.getId());
			currentRouter.setOfSwitch(sw);
			logger.info("ROUTER {} UNDER CONTROL", sw.getId());
		} else {

			if (!switches.containsKey(sw.getId())) {
				switches.put(sw.getId(), new HashMap<MacAddress, OFPort>());
			}
			Map<MacAddress, OFPort> mapOfCurrentSwitch = switches.get(sw
					.getId());
			OFPort outPort = OFPort.FLOOD;
			if (mapOfCurrentSwitch.containsKey(ethernet
					.getDestinationMACAddress())) {
				outPort = mapOfCurrentSwitch.get(ethernet
						.getDestinationMACAddress());
				pushEthernetFlow(sw, ethernet.getSourceMACAddress(), inPort,
						outPort);
			}
			pushPacket(ethernet, sw, OFBufferId.NO_BUFFER, inPort, outPort);
			mapOfCurrentSwitch.put(ethernet.getSourceMACAddress(), inPort);

			return Command.STOP;
		}

		// obrada ARP zahtjeva
		if ((ethernet.getPayload() instanceof ARP)) {
			ARP arp = (ARP) ethernet.getPayload();
			if (currentRouter.getSubnet().isGateway(
					IPv4Address.of(arp.getTargetProtocolAddress()))) {

				pushArpResponse(sw, ethernet, CustomRouter.SUBNET_PORT);
			}
			return Command.STOP;
		}

		// rutiranje IPv4 paketa
		if ((ethernet.getPayload() instanceof IPv4)) {
			IPv4 ip = (IPv4) ethernet.getPayload();

			if (ipHistory.containsKey(ip)
					&& ipHistory.get(ip).equals(sw.getId())) {
				return Command.STOP;
			}
			ipHistory.put(ip, sw.getId());

			// source router
			if (currentRouter.getSubnet().isHostInSubnet(ip.getSourceAddress())) {

				// search for destination router
				CustomRouter destinationRouter = getDestinationRouter(ip
						.getDestinationAddress());
				if (destinationRouter != null) {

					// find route between two routers
					Route route = routingProvider.getRoute(sw.getId(),
							destinationRouter.getId(), null);

					if (route.getPath().size() >= 2) {
						NodePortTuple first = route.getPath().remove(0);
						NodePortTuple last = route.getPath().remove(
								route.getPath().size() - 1);

						// rewrite destination MAC
						Ethernet rewritedPacket = new Ethernet();
						rewritedPacket.deserialize(pi.getData(), 0,
								pi.getData().length);
						rewritedPacket
								.setDestinationMACAddress(destinationRouter
										.getOfSwitch()
										.getPort(last.getPortId()).getHwAddr());
						rewritedPacket.serialize();

						// Add flows all along the way
						for (int i = 0; i < route.getPath().size() - 1; i += 2) {
							NodePortTuple in = route.getPath().get(i);
							NodePortTuple out = route.getPath().get(i + 1);
							pushIpFlow(
									switchProvider.getSwitch(in.getNodeId()),
									ip.getDestinationAddress(), in.getPortId(),
									rewritedPacket.getDestinationMACAddress(),
									out.getPortId());
							pushIpFlow(
									switchProvider.getSwitch(in.getNodeId()),
									ip.getSourceAddress(), out.getPortId(),
									ethernet.getSourceMACAddress(),
									in.getPortId());
							logger.info("ADD ROUTE TO SWITCH IN "
									+ in.getNodeId() + " PORT "
									+ in.getPortId() + " SWITCH OUT "
									+ out.getNodeId() + " PORT "
									+ out.getPortId());
						}

						// send current packet
						pushPacket(rewritedPacket, sw, OFBufferId.NO_BUFFER,
								OFPort.ANY, sw.getPort(first.getPortId())
										.getPortNo());

						// add flow to current router
						pushIpFlow(sw, ip.getDestinationAddress(),
								CustomRouter.SUBNET_PORT,
								rewritedPacket.getDestinationMACAddress(),
								first.getPortId());
						pushIpFlow(sw, ip.getSourceAddress(), last.getPortId(),
								ethernet.getSourceMACAddress(),
								CustomRouter.SUBNET_PORT);
					}
				}
			}

			// destination router
			if (currentRouter.getSubnet().isHostInSubnet(
					ip.getDestinationAddress())) {

				Ethernet rewritedPacket = new Ethernet();
				rewritedPacket
						.deserialize(pi.getData(), 0, pi.getData().length);

				// search destination device
				Device host = getDeviceByAddress(ip.getDestinationAddress(),
						null);
				if (host == null) {
					return Command.STOP;
				}
				// rewrite destination MAC
				rewritedPacket.setDestinationMACAddress(host.getMACAddress());
				rewritedPacket.serialize();

				// send current packet
				pushPacket(rewritedPacket, sw, OFBufferId.NO_BUFFER,
						OFPort.ANY, sw.getPort(CustomRouter.SUBNET_PORT)
								.getPortNo());

				// add flow to current router
				pushIpFlow(sw, ip.getDestinationAddress(), inPort,
						rewritedPacket.getDestinationMACAddress(),
						CustomRouter.SUBNET_PORT);
				pushIpFlow(sw, ip.getSourceAddress(), CustomRouter.SUBNET_PORT,
						ethernet.getSourceMACAddress(), inPort);
			}
		}
		return Command.STOP;
	}

	// get router responsible for subnet in which IP address belongs
	private CustomRouter getDestinationRouter(IPv4Address address) {
		for (DatapathId id : routers.keySet()) {
			if (routers.get(id).getSubnet().isHostInSubnet(address)) {
				routers.get(id).setOfSwitch(switchProvider.getSwitch(id));
				return routers.get(id);
			}
		}
		return null;
	}

	// search known device by IP or MAC address
	public Device getDeviceByAddress(IPv4Address ipAdress, MacAddress macAddress) {
		try {
			Iterator<? extends IDevice> iter = deviceProvider.queryDevices(
					macAddress, null, ipAdress, null, null);
			if (iter.hasNext()) {
				return (Device) iter.next();
			}
		} catch (Exception e) {
			return null;
		}
		return null;
	}

	// push flow to OF switch with IP match and MAC destination rewrite
	public void pushIpFlow(IOFSwitch sw, IPv4Address matchIp, OFPort in,
			MacAddress destinationMac, OFPort out) {

		OFFactory myFactory = sw.getOFFactory();
		Match myMatch = myFactory.buildMatch().setExact(MatchField.IN_PORT, in)
				.setExact(MatchField.ETH_TYPE, EthType.IPv4)
				.setExact(MatchField.IPV4_DST, matchIp).build();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
		OFActions actions = myFactory.actions();
		OFActionSetDlDst setDlDst = actions.buildSetDlDst()
				.setDlAddr(destinationMac).build();
		actionList.add(setDlDst);
		OFActionOutput output = actions.buildOutput()
				.setMaxLen(Integer.MAX_VALUE).setPort(out).build();
		actionList.add(output);
		OFFlowAdd flowAdd = myFactory.buildFlowAdd()
				.setBufferId(OFBufferId.NO_BUFFER)
				.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
				.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
				.setPriority(FLOWMOD_PRIORITY).setMatch(myMatch)
				.setOutPort(out).setActions(actionList).build();

		logger.info("PUSHING IP FLOW TO SWITCH  " + sw.getId() + " MATCH "
				+ matchIp + " ON PORT " + in + " ACTION REWRITE MAC "
				+ destinationMac + " OUT TO PORT " + out);

		sw.write(flowAdd);
		sw.flush();

	}

	// push flow to OF switch with MAC address match
	public void pushEthernetFlow(IOFSwitch sw, MacAddress matchMac, OFPort in,
			OFPort out) {

		OFFactory myFactory = sw.getOFFactory();
		Match myMatch = myFactory.buildMatch().setExact(MatchField.IN_PORT, in)
				.setExact(MatchField.ETH_SRC, matchMac).build();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
		OFActions actions = myFactory.actions();
		OFActionOutput output = actions.buildOutput()
				.setMaxLen(Integer.MAX_VALUE).setPort(out).build();
		actionList.add(output);
		OFFlowAdd flowAdd = myFactory.buildFlowAdd()
				.setBufferId(OFBufferId.NO_BUFFER)
				.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
				.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
				.setPriority(FLOWMOD_PRIORITY).setMatch(myMatch)
				.setOutPort(out).setActions(actionList).build();

		logger.info("PUSHING ETH FLOW TO SWITCH  " + sw.getId() + " MATCH "
				+ matchMac + " ON PORT " + in + " OUT TO PORT " + out);

		sw.write(flowAdd);
		sw.flush();

	}

	// inject single packet to switch
	public void pushPacket(IPacket packet, IOFSwitch sw, OFBufferId bufferId,
			OFPort inPort, OFPort outPort) {

		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(sw.getOFFactory().actions().buildOutput().setPort(outPort)
				.setMaxLen(Integer.MAX_VALUE).build());
		pob.setActions(actions);
		pob.setBufferId(bufferId);
		pob.setInPort(inPort);
		if (pob.getBufferId() == OFBufferId.NO_BUFFER) {
			if (packet == null) {
				return;
			}
			byte[] packetData = packet.serialize();
			pob.setData(packetData);
		}

		logger.info("PUSHING PACKET TO SWITCH {} PORT {}", sw.getId(), outPort);

		sw.write(pob.build());
		sw.flush();
	}

	// generate and send ARP response
	public void pushArpResponse(IOFSwitch sw, Ethernet ethernet, OFPort out) {

		MacAddress macAddress = sw.getPort(CustomRouter.SUBNET_PORT)
				.getHwAddr();
		ARP arpRequest = (ARP) ethernet.getPayload();
		IPacket arpReply = new Ethernet()
				.setSourceMACAddress(macAddress.getBytes())
				.setDestinationMACAddress(ethernet.getSourceMACAddress())
				.setEtherType(Ethernet.TYPE_ARP)
				.setVlanID(ethernet.getVlanID())
				.setPriorityCode(ethernet.getPriorityCode())
				.setPayload(
						new ARP()
								.setHardwareType(ARP.HW_TYPE_ETHERNET)
								.setProtocolType(ARP.PROTO_TYPE_IP)
								.setHardwareAddressLength((byte) 6)
								.setProtocolAddressLength((byte) 4)
								.setOpCode(ARP.OP_REPLY)
								.setSenderHardwareAddress(macAddress.getBytes())
								.setSenderProtocolAddress(
										arpRequest.getTargetProtocolAddress())
								.setTargetHardwareAddress(
										ethernet.getSourceMACAddress()
												.getBytes())
								.setTargetProtocolAddress(
										arpRequest.getSenderProtocolAddress()));

		Device host = getDeviceByAddress(null,
				MacAddress.of(arpRequest.getSenderHardwareAddress()));
		if (host != null) {
			IOFSwitch swt = switchProvider
					.getSwitch(host.getAttachmentPoints()[0].getSwitchDPID());

			logger.info("PUSHING ARP RESPONSE FOR HOST {} TO SWITCH {}",
					MacAddress.of(arpRequest.getSenderHardwareAddress()),
					swt.getId());

			pushPacket(arpReply, swt, OFBufferId.NO_BUFFER, OFPort.ANY,
					host.getAttachmentPoints()[0].getPort());
		}
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

		File file = new File("customrouter.properties");

		try {
			BufferedReader in = new BufferedReader(new FileReader(file));
		} catch (FileNotFoundException e) {
			file = new File(getClass().getClassLoader().getResource("customrouter.properties")
					.getFile());
		}

		try {
			BufferedReader in = new BufferedReader(new FileReader(file));
			String line = in.readLine();
			while (line != null) {
				logger.info(line);
				if (!line.startsWith("#")) {
					String[] params = line.split(",");
					CustomRouter cr = new CustomRouter();
					cr.setId(DatapathId.of(Integer.valueOf(params[0].trim())));
					cr.setSubnet(new Subnet(IPv4Address.of(params[1].trim()),
							Integer.valueOf(params[2].trim()), IPv4Address
									.of(params[3].trim())));

					routers.put(cr.getId(), cr);
					logger.info(cr.toString());
				}
				line = in.readLine();
			}

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		linkDiscoveryProvider = context
				.getServiceImpl(ILinkDiscoveryService.class);
		deviceProvider = context.getServiceImpl(IDeviceService.class);
		switchProvider = context.getServiceImpl(IOFSwitchService.class);
		routingProvider = context.getServiceImpl(IRoutingService.class);
		logger = LoggerFactory.getLogger(CustomRouterModule.class);
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getName() {
		return "Custom Router v1.0";
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> floodlightService = new ArrayList<Class<? extends IFloodlightService>>();
		floodlightService.add(IFloodlightProviderService.class);
		floodlightService.add(ILinkDiscoveryService.class);
		floodlightService.add(IDeviceService.class);
		floodlightService.add(IOFSwitchService.class);
		return floodlightService;
	}
	// src/main/floodlight/floodlightdefault.properties
}
