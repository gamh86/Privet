import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Iterator;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PrivetRegister
{
  private Short type;
  private String host;
  private List<String> aliases;
  
  private class NameType
  {
    public String name;
    public Short type;
    
    NameType(String n, Short t)
    {
      name = n;
      type = t;
    }
  }
  
  private ByteBuffer encodeData(List<NameType> list)
  {
    byte[] data = new byte[8192];
    ByteBuffer buffer = ByteBuffer.wrap(data);
    int pos = 0;
    Map<String,Short> labels = new HashMap<String,Short>();
    boolean need_null = true;
    
    Iterator<NameType> iter = list.iterator();
    while (iter.hasNext())
    {
      NameType ntype = iter.next();
      List<String> tokens = ArrayList(Arrays.asList(ntype.name.split('.',0)));
      Iterator<String> t_iter = tokens.iterator();
      need_null = true;
      
      while (t_iter.hasNext())
      {
        String token = t_iter.next();
        if (labels.containsKey(token))
        {
          short offset = labels.get(token);
          offset += (0x100 * 0xc0);
          buffer.putShort(offset);
          need_null = false;
          break;
        }
        else
        {
          short offset = (short)((short)12 + (short)buffer.position());
          labels.put(token, offset);
          byte[] token_raw = token.getBytes();
          pos = buffer.position();
          data[pos++] = (byte)token.length();
          System.arraycopy(token_raw, 0, data, pos, token.length());
          pos += token.length() + 1;
          buffer.position(pos);
        }
      }
      
      if (need_null == true)
      {
        data[pos++] = (byte)0;
        buffer.position(pos);
      }
      
      buffer.putShort(ntype.type);
      buffer.putShort((short)1);
    }
    
    return buffer;
  }
  
  PrivetRegister(String service, List<String> aliases)
  {
    Privet privet = new Privet();
    
    byte[] data = new byte[8192];
    ByteBuffer buffer = ByteBuffer.wrap(data);
    
    buffer.putShort((short)0);
    buffer.putShort((short)0x8000);
    buffer.putShort((short)aliases.size() + 1);
    buffer.putShort((short)0);
    buffer.putShort((short)0);
    buffer.putShort((short)0);
    
    List<NameType> pre;
    serv = new NameType(service, (short)33);
    pre.add(serv);
    Iterator<String> iter = aliases.iterator();
    while (iter.hasNext())
      pre.add(iter.next(), (short)1);
    encoded = encodeData(pre);
  }
}
