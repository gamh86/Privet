import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class Privet
{
	protected static final String mDNS_ipv4 = "224.0.0.251";
	protected static final String mDNS_ipv6 = "ff02::fb";
	protected static final Short mDNS_port = 5353;
	protected static final Map<String,Short> mdns_types = __create_types_map();
	protected static final Map<String,Short> mdns_classes = __create_classes_map();
	protected static final short mdns_header_size = (short)12;
	protected static final byte DNS_JUMP_INDICATOR = (byte)0xc0;
	protected static final short DNS_JUMP_OFFSET_BIAS = (short)((short)0x100 * (short)0xc0);
	protected static final int query_interval = 600000; /* milliseconds */
	protected static final String SPECIAL_QUERY_ALL = "_services._dns-sd._udp.local";
	protected static final String QUERY_HTTP = "_http._tcp.local";
	protected static final String QUERY_PRINTER = "_ipp._tcp.local";
	
	protected long time_last_query;
	
	private boolean should_query()
	{
		if ((System.currentTimeMillis() - time_last_query) >= query_interval)
			return true;
		
		return false;
	}
	
	public class NameTypePair
	{
		String name;
		Short type;
		
		NameTypePair(String n, Short t)
		{
			name = n;
			type = t;
		}
	}

	protected class ServerRecord
	{
		private Short priority;
		private Short weight;
		private Short port;
		private String target;

		ServerRecord() {}

		public Short getPriority()
		{
			return priority;
		}

		public Short getWeight()
		{
			return weight;
		}

		public Short getPort()
		{
			return port;
		}

		public String getTarget()
		{
			return target;
		}

		public void setPriority(short p)
		{
			priority = p;
		}

		public void setWeight(short w)
		{
			weight = w;
		}

		public void setPort(short p)
		{
			port = p;
		}

		public void setTarget(String t)
		{
			target = t;
		}
	}

	protected class mDNSRecord
	{
		private String name;
		private Short type;
		private Short klass;
		private Integer ttl;
		private InetAddress inet4;
		private InetAddress inet6;
		private Map<String,String> text_record;
		private String pointer;
		private ServerRecord server_record;

		mDNSRecord()
		{
			name = null;
			type = (short)0;
			klass = (short)0;
			ttl = (int)0;
			inet4 = null;
			inet6 = null;
			text_record = null;
			pointer = null;
			server_record = null;
		}

		public void setName(String n)
		{
			name = n;
		}

		public void setType(Short t)
		{
			type = t;
		}

		public void setClass(Short c)
		{
			klass = c;
		}

		public void setTTL(int t)
		{
			ttl = t;
		}

		public void setInet4(InetAddress i)
		{
			inet4 = i;
		}

		public void setInet6(InetAddress i)
		{
			inet6 = i;
		}

		public void setServerRecord(ServerRecord r)
		{
			server_record = r;
		}

		public void setTextRecord(Map<String,String> t)
		{
			text_record = t;
		}

		public void setPointer(String p)
		{
			pointer = p;
		}

		public String getName()
		{
			return name;
		}

		public Short getType()
		{
			return type;
		}

		public Short getKlass()
		{
			return klass;
		}

		public Integer getTTL()
		{
			return ttl;
		}

		public InetAddress getInet4()
		{
			return inet4;
		}

		public InetAddress getInet6()
		{
			return inet6;
		}

		public ServerRecord getServerRecord()
		{
			return server_record;
		}

		public Map<String,String> getTextRecord()
		{
			return text_record;
		}

		public String getPointer()
		{
			return pointer;
		}
	}

	protected static Map<String,Short> __create_types_map()
	{
		Map<String,Short> __static_types_map = new HashMap<String,Short>();
		__static_types_map.put("A", (short)1);
		__static_types_map.put("PTR", (short)12);
		__static_types_map.put("TXT", (short)16);
		__static_types_map.put("AAAA", (short)28);
		__static_types_map.put("SRV", (short)33);
		__static_types_map.put("ANY", (short)255);
		return Collections.unmodifiableMap(__static_types_map);
	}

	protected static Map<String,Short> __create_classes_map()
	{
		Map<String,Short> __static_classes_map = new HashMap<String,Short>();
		__static_classes_map.put("IN", (short)1);
		return Collections.unmodifiableMap(__static_classes_map);
	}

	protected static MulticastSocket sock;
	private static InetAddress mcast_group;

	private List<mDNSRecord> records;

	public Privet()
	{
		try
		{
			mcast_group = InetAddress.getByName(mDNS_ipv4);
			sock = new MulticastSocket(mDNS_port);
			sock.setLoopbackMode(true); /* setLoopbackMode(boolean disable) */
			sock.joinGroup(mcast_group);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			System.exit(1);
		}
		finally
		{
			records = new ArrayList<mDNSRecord>();
			System.out.println("Joined multicast group " + mDNS_ipv4);
		}
	}

	/*
	 * Query for the list of service types
	 * stored in List<String> services.
	 */
	public void queryServices()
	{
		ArrayList<NameTypePair> list = new ArrayList<NameTypePair>();
		NameTypePair pair = new NameTypePair(SPECIAL_QUERY_ALL, mdns_types.get("PTR"));
		ByteBuffer header = ByteBuffer.allocate(12);

		list.add(pair);
		ByteBuffer data = encodeData(list);

		header.putShort((short)0);
		header.putShort((short)0);
		header.putShort((short)1);
		header.putShort((short)0);
		header.putShort((short)0);
		header.putShort((short)0);

		byte[] packet_bytes = new byte[12 + data.position()];

		try
		{
			System.arraycopy(header.array(), 0, packet_bytes, 0, 12);
			System.arraycopy(data.array(), 0, packet_bytes, 12, data.position());
			ByteBuffer wrapper = ByteBuffer.wrap(packet_bytes);
			DatagramPacket packet = new DatagramPacket(packet_bytes, packet_bytes.length, mcast_group, mDNS_port);
			sock.send(packet);
			time_last_query = System.currentTimeMillis();
		}
		catch (Exception e)
		{
			e.printStackTrace();
			System.exit(1);
		}
	}

	protected void parseQueries(ByteBuffer buffer, int nr_qs)
	{
		byte[] data = buffer.array();

		buffer.position(12);

		for (int i = 0; i < nr_qs; ++i)
		{
			String name = decodeName(buffer);

			short type = buffer.getShort();
			short klass = buffer.getShort();
			String host = new String(name);

			klass &= ~((short)0x8000);
			System.out.println(" Host          " + host);
			System.out.println(" Type          " + type);
			System.out.println(" Class         " + klass + "\n");
		}

		return;
	}

	protected String decodeName(ByteBuffer buffer)
	{
		byte[] data = buffer.array();
		byte[] name = new byte[256];
		byte len;
		int pos = buffer.position();
		int n = 0;
		boolean jumped = false;
		ArrayList<Integer> positions = new ArrayList<Integer>();

		while (true)
		{
			len = data[pos];
			if (len == (byte)0)
				break;
			else
			if ((len & DNS_JUMP_INDICATOR) == DNS_JUMP_INDICATOR)
			{
				buffer.position(pos);
				short offset = buffer.getShort();
				positions.add(buffer.position());
				offset -= DNS_JUMP_OFFSET_BIAS;
				pos = (int)offset;
				jumped = true;

				continue;
			}
			else
			{
				if (n > 0)
					name[n++] = (byte)'.';

				pos += 1;
				System.arraycopy(data, pos, name, n, (int)len);
				pos += (int)len;
				n += (int)len;
			}
		}

/*
 * If we jumped back then the buffer position
 * is already at the right place.
 */
		if (jumped == true)
		{
			buffer.position(positions.get(0));
		}
		else
		{
			buffer.position(pos+1);
		}

		String __name = new String(name);
		return __name;
	}

	protected String getType(short type)
	{
		for (Map.Entry<String,Short> entry : mdns_types.entrySet())
		{
			if (type == entry.getValue())
				return entry.getKey();
		}

		return new String("Unknown Type");
	}

	protected String getKlass(short klass)
	{
		for (Map.Entry<String,Short> entry : mdns_classes.entrySet())
		{
			if (klass == entry.getValue())
				return entry.getKey();
		}

		return new String("Unknown Class");
	}

	protected Map<String,String> parseTextRecord(ByteBuffer buffer, int data_len)
	{
		int kvlen = 0;
		byte[] data = buffer.array();
		int pos = buffer.position();
		Map<String,String> text = new HashMap<String,String>();

		System.out.println(" Text");
		if (data_len == 1)
		{
			buffer.position(buffer.position()+1);
			return text;
		}

		while (true)
		{
			if (data_len <= 0)
				break;

			kvlen = ((int)data[pos] & 0xff);
			if (kvlen == 0)
				break;

			pos += 1;
			--data_len;
			byte[] kvpair = new byte[kvlen];
			System.arraycopy(data, pos, kvpair, 0, kvlen);
			String pair_str = new String(kvpair);
			System.out.println("    >          " + pair_str);
			String[] pair_split = pair_str.split("=", 0);
			if (pair_split.length == 1)
				text.put(pair_split[0], "");
			else
				text.put(pair_split[0], pair_split[1]);
			pos += kvlen;
			data_len -= kvlen;
		}

		buffer.position(pos);
		return text;
	}

	protected void parseRecords(ByteBuffer buffer, short nr_answers)
	{
		byte len;
		byte[] data = buffer.array();
		boolean jumped = false;
		int pos = buffer.position();
		int n = 0;

		for (int i = 0; i < (int)nr_answers; ++i)
		{
			String name = decodeName(buffer);

			short type = buffer.getShort();
			short klass = buffer.getShort();
			int ttl = buffer.getInt();
			short data_len = buffer.getShort();

			klass &= ~((short)0x8000);

			mDNSRecord record = new mDNSRecord();

			record.setName(name);
			record.setType(type);
			record.setClass(klass);
			record.setTTL(ttl);

			pos = buffer.position();
			System.out.println(" Name          " + name);
			System.out.println(" Type          " + getType(type) + " (" + type + ")");
			System.out.println(" Class         " + getKlass(klass) + " (" + klass + ")");
			System.out.println(" TTL           " + ttl + " seconds");

			switch(type)
			{
				case 1:
				byte[] ipv4_bytes = new byte[4];
				InetAddress inet4 = null;
				System.arraycopy(data, buffer.position(), ipv4_bytes, 0, data_len);
				pos += (int)data_len;
				buffer.position(pos);
				try
				{
					inet4 = InetAddress.getByAddress(ipv4_bytes);
				}
				catch (Exception e)
				{
					e.printStackTrace();
					System.exit(1);
				}
				record.setInet4(inet4);
				System.out.println(" IPv4 Address  " + inet4.getHostAddress() + "\n");
				break;
				case 12:
				String _name = decodeName(buffer);
				System.out.println(" Pointer       " + _name + "\n");
				pos = buffer.position();
				record.setPointer(_name);
				break;
				case 16:
				Map<String,String> text_record = parseTextRecord(buffer, (int)data_len);
				pos = buffer.position();
				System.out.println("");
				record.setTextRecord(text_record);
				break;
				case 28:
				byte[] ipv6_bytes = new byte[16];
				InetAddress inet6 = null;
				System.arraycopy(data, pos, ipv6_bytes, 0, 16);
				try
				{
					inet6 = InetAddress.getByAddress(ipv6_bytes);
				}
				catch (Exception e)
				{
					e.printStackTrace();
					System.exit(1);
				}
				record.setInet6(inet6);
				System.out.println(" IPv6 Address  " + inet6.getHostAddress() + "\n");
				pos += 16;
				buffer.position(pos);
				break;
				case 33:
				short prio = buffer.getShort();
				short weight = buffer.getShort();
				short port = buffer.getShort();
				String target = decodeName(buffer);
				ServerRecord server = new ServerRecord();
				server.setPriority(prio);
				server.setWeight(weight);
				server.setPort(port);
				server.setTarget(target);
				record.setServerRecord(server);
				pos = buffer.position();
				System.out.println(" Priority      " + prio);
				System.out.println(" Weight        " + weight);
				System.out.println(" Port          " + port);
				System.out.println(" Target        " + target + "\n");
				break;
				default:
				pos += (int)data_len;
				buffer.position(pos);
				System.out.println("");
			}

			records.add(record);
		} /* for (i = 0; i < nr_answers; ++i) */
	}

	public void getReplies()
	{
		byte[] data = new byte[8192];
		DatagramPacket packet = new DatagramPacket(data, data.length);

		try
		{
			sock.receive(packet);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			System.exit(1);
		}

		byte[] header = new byte[12];
		data = packet.getData();

		System.arraycopy(data, 0, header, 0, 12);
		ByteBuffer header_w = ByteBuffer.wrap(header);
		header_w.position(4);
		short nr_qs = header_w.getShort();
		short nr_as = header_w.getShort();
		short nr_aa = header_w.getShort();
		short nr_ad = header_w.getShort();

		System.out.println("Received mDNS packet with:");
		System.out.println(nr_qs + " queries; " + nr_as + " answers; " + nr_aa + " authoritative answers; " + nr_ad + " additional answers" + "\n");

		ByteBuffer buf = ByteBuffer.wrap(data);
		buf.position(12);

		if (nr_qs > 0)
			parseQueries(buf, nr_qs);

		short total_answers = (short)(nr_as + nr_aa + nr_ad);
		parseRecords(buf, total_answers);

		return;
	}

	protected List<String> tokenizeName(String name, byte c)
	{
		List<String> tokens = new ArrayList<String>(Arrays.asList(name.split("\\.", 0)));
		return tokens;
	}

	protected ByteBuffer encodeData(List<NameTypePair> services)
	{
		ByteBuffer bbuf = ByteBuffer.allocate(8192);
		List<String> tokens = null;
		Map<String,Short> labels = new HashMap<String,Short>();
		boolean need_null = true;
		byte delim = (byte)'.';

		bbuf.order(ByteOrder.BIG_ENDIAN);

		try
		{
			Iterator<NameTypePair> iter = services.iterator();
			while (iter.hasNext())
			{
				NameTypePair pair = iter.next();
				tokens = tokenizeName(pair.name, delim);

				for (int j = 0; j < tokens.size(); ++j)
				{
					String token = tokens.get(j);

					if (labels.containsKey(token) == true)
					{
						short offset = labels.get(token);
						offset += (0xc0 * 0x100);
						bbuf.putShort(offset);

						need_null = false;
						break;
					}
					else
					{
						short pos = (short)bbuf.position();
						short offset = (short)(mdns_header_size + (short)pos);
						labels.put(token, offset);

						byte[] len = new byte[1];
						len[0] = (byte)token.length();
						byte[] token_bytes = token.getBytes();
						bbuf.put(len, 0, 1);
						bbuf.put(token_bytes, 0, token.length());
					}
				}

				if (need_null == true)
				{
					byte[] _null = new byte[1];
					_null[0] = (byte)0;
					bbuf.put(_null, 0, 1);
				}
				else
					need_null = true;

				bbuf.putShort(pair.type);
				bbuf.putShort(mdns_classes.get("IN"));
			}
		}
		catch (Exception e)
		{
			e.printStackTrace();
			System.exit(1);
		}

		return bbuf;
	}

	public void dumpCachedRecords()
	{
		Iterator<mDNSRecord> iter = records.iterator();
		while (iter.hasNext())
		{
			mDNSRecord record = iter.next();
			System.out.println("Name  " + record.getName());
			System.out.println("Type  " + record.getType());
			System.out.println("Class  " + record.getKlass());
			InetAddress inet4 = record.getInet4();
			if (null != inet4)
				System.out.println("IPv4  " + inet4.getHostAddress());
			InetAddress inet6 = record.getInet6();
			if (null != inet6)
				System.out.println("IPv6  " + inet6.getHostAddress());
			String ptr = record.getPointer();
			if (null != ptr)
				System.out.println("Pointer  " + ptr);
			Map<String,String> text = record.getTextRecord();
			if (null != text)
			{
				for (Map.Entry<String,String> entry : text.entrySet())
					System.out.println(entry.getKey() + "=" + entry.getValue());
			}
		}
	}

	public void showLocalServices()
	{
		Iterator<mDNSRecord> iter = records.iterator();
		while (iter.hasNext())
		{
			mDNSRecord record = iter.next();
			String ptr = record.getPointer();
			if (null != ptr)
				System.out.println(ptr);
		}
	}

	public static void main(String argv[])
	{
		Privet privet = new Privet();

		privet.queryServices();
		privet.getReplies();
		privet.showLocalServices();
		System.exit(0);
	}
}
