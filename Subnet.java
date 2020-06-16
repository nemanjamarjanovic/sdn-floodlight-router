package net.floodlightcontroller.customrouter;

import java.util.Arrays;

import org.projectfloodlight.openflow.types.IPv4Address;

public class Subnet {

	private IPv4Address address;
	private int mask;
	private IPv4Address gatewayAddress;

	public Subnet(IPv4Address address, int mask, IPv4Address gatewayAddress) {
		super();
		this.address = address;
		this.mask = mask;
		this.gatewayAddress = gatewayAddress;
	}

	public boolean isHostInSubnet(IPv4Address hostAddress) {

		byte[] subnet = this.address.getBytes();
		byte[] host = hostAddress.getBytes();

		int offset = mask / 8;
		int remainder = mask % 8;
		byte maskb = (byte) (0xFF << (8 - remainder));
		if (offset < host.length)
			host[offset] = (byte) (host[offset] & maskb);
		offset++;
		for (; offset < host.length; offset++) {
			host[offset] = 0;
		}

		return Arrays.equals(host, subnet);
	}

	public boolean isGateway(IPv4Address gatewayAddress) {
		return this.gatewayAddress.equals(gatewayAddress);
	}

	@Override
	public String toString() {

		return "SUBNET: " + address.toString() + " MASK: " + mask
				+ " GATEWAY: " + gatewayAddress.toString();
	}

}
