package net.floodlightcontroller.customrouter;

import net.floodlightcontroller.core.IOFSwitch;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;

public class CustomRouter {

	public static final OFPort SUBNET_PORT = OFPort.of(1);
	// public static final OFPort FOREIGN_PORT = OFPort.of(2);

	private DatapathId id;
	private IOFSwitch ofSwitch;
	private Subnet subnet;

	public DatapathId getId() {
		return id;
	}

	public void setId(DatapathId id) {
		this.id = id;
	}

	public IOFSwitch getOfSwitch() {
		return ofSwitch;
	}

	public void setOfSwitch(IOFSwitch ofSwitch) {
		this.ofSwitch = ofSwitch;
	}

	public Subnet getSubnet() {
		return subnet;
	}

	public void setSubnet(Subnet subnet) {
		this.subnet = subnet;
	}

	@Override
	public String toString() {

		return "ROUTER ID: " + id + " " + subnet.toString();
	}

}
