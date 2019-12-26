import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PrivetRegister extends Privet
{
  private Short type;
  private String host;
  private List<String> aliases;
  
  PrivetRegister(String h, List<String> a)
  {
    super(); /* Privet class will open Multicast socket and join group 224.0.0.251 */
    host = h;
    aliases = a;
  }

	private InetAddress getLocalIPv4()
	{
		InetAddress inet = null;

/*
 * TODO:
 *
 * Loop through the different interaces on
 * the system and find a suitable canditate.
 */
		try
		{
			NetworkInterface iface = NetworkInterface.getByName("wlp2s0");
			Enumeration<InetAddress> inets = iface.getInetAddresses();
			inet = inets.nextElement();
		}
		catch (Exception e)
		{
			e.printStackTrace();
			System.exit(1);
		}
		finally
		{
			System.out.println("Got local ip: " + inet.getHostAddress());
			return inet;
		}
	}

	private ByteBuffer encodeName(String name)
	{
		ByteBuffer buffer = ByteBuffer.allocate(6000);
		List<String> tokens = tokenizeName(name, (byte)'.');
		int pos = 0;
		boolean need_null = false;

		if (tokens.isEmpty())
			return buffer;

		buffer.order(ByteOrder.BIG_ENDIAN);

		Iterator<String> iter = tokens.iterator();
		while (iter.hasNext())
		{
			String token = iter.next();
			if (label_cache.containsKey(token))
			{
				short offset = label_cache.get(token);
				offset += DNS_JUMP_OFFSET_BIAS;
				buffer.putShort(offset);
				pos = buffer.position();
				need_null = false;
				break;
			}
			else
			{
				short offset = (short)((short)12 + (short)buffer.position());
				label_cache.put(token, offset);
				byte[] data = buffer.array();
				pos = buffer.position();
				data[pos++] = (byte)token.length();
				System.arraycopy(token.getBytes(), 0, data, pos, token.length());
				pos += token.length();
				buffer.position(pos);
			}
		}

		if (true == need_null)
		{
			pos = buffer.position();
			byte[] data = buffer.array();
			data[pos++] = (byte)0;
			buffer.position(pos);
		}

		return buffer;
	}

	private ByteBuffer createSRVQuery(String host, String alias, InetAddress inet)
	{
		ByteBuffer buffer = ByteBuffer.allocate(6000);
		byte[] data = null;
		int pos = 0;
		
		clearLabelCache();

		ByteBuffer encoded_host = encodeName(host);
		System.arraycopy(encoded_host.array(), 0, buffer.array(), pos, encoded_host.position());
		pos += encoded_host.position();
		buffer.position(pos);
		buffer.putShort(mdns_types.get("SRV"));
		buffer.putShort(mdns_classes.get("IN"));
		pos = buffer.position();
		ByteBuffer encoded_alias = encodeName(alias);
		System.arraycopy(encoded_alias.array(), 0, buffer.array(), pos, encoded_alias.position());
		pos += encoded_alias.position();
		buffer.putShort(mdns_types.get("A"));
		buffer.putShort(mdns_classes.get("IN"));
		pos = buffer.position();
		System.arraycopy(inet.getAddress(), 0, buffer.array(), pos, 4);
		pos += 4;
		buffer.position(pos);

		return buffer;
	}

	/**
	 * Register a service.
	 * Query our own service first to detect the
	 * unlikely event that a service of that name
	 * already exists on the local network.
	 */
	public void registerService()
	{
		ByteBuffer SRVQuery = createSRVQuery("_http._tcp.local", "home-movies.local", getLocalIPv4());
		ByteBuffer mdns_header = ByteBuffer.allocate(12);

		mdns_header.putShort((short)0);
		mdns_header.putShort((short)0);
		mdns_header.putShort((short)2);
		mdns_header.putShort((short)0);
		mdns_header.putShort((short)0);
		mdns_header.putShort((short)0);

		byte[] packet = new byte[12 + SRVQuery.position()];
		byte[] packet_in = new byte[8192];

		DatagramPacket dgram_packet = new DatagramPacket(packet, packet.length, mcast_group, mDNS_port);
		DatagramPacket dgram_in = new DatagramPacket(packet_in, packet_in.length);

		System.arraycopy(mdns_header.array(), 0, packet, 0, 12);
		System.arraycopy(SRVQuery.array(), 0, packet, 12, SRVQuery.position());

		try
		{
			sock.send(dgram_packet);
			sock.receive(dgram_in);
		}
		catch(Exception e)
		{
			e.printStackTrace();
			System.exit(1);
		}
	}

	public static void main(String argv[])
	{
		List<String> aliases = new ArrayList<String>();
		aliases.add("home-movies.local");
		PrivetRegister reg = new PrivetRegister("_http._tcp.local", aliases);
		reg.registerService();
	}
}
