import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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
  
  PrivetRegister(String service, List<String> aliases)
  {
    byte[] data = new byte[8192];
    ByteBuffer buffer = ByteBuffer.wrap(data);
    
    buffer.putShort((short)0);
    buffer.putShort((short)0x8000);
    buffer.putShort((short)aliases.size() + 1);
    buffer.putShort((short)0);
    buffer.putShort((short)0);
    buffer.putShort((short)0);
    
    List<NameTypePair> pre;
    NameTypePair pair = new NameTypePair(service, (short)33);
    pre.add(pair);
    Iterator<String> iter = aliases.iterator();
    while (iter.hasNext())
    {
      pair = new NameTypePair(iter.next(), (short)1);
      pre.add(pair);
    }
    encoded = encodeData(pre);
  }
}
