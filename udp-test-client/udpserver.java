//code from internet

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

public class udpserver
{
    public static void main(String[] args) throws IOException
    {
        DatagramSocket ds = new DatagramSocket(2333);
        byte[] receive = new byte[65535];

        DatagramPacket DpReceive = null;
        while (true)
        {

            DpReceive = new DatagramPacket(receive, receive.length);

            ds.receive(DpReceive);

            System.out.println("Client:-" + data(receive));

            if (data(receive).toString().equals("bye"))
            {
                break;
            }

            receive = new byte[65535];
        }
    }

    //
    public static StringBuilder data(byte[] a)
    {
        if (a == null)
            return null;
        StringBuilder ret = new StringBuilder();
        int i = 0;
        while (a[i] != 0)
        {
            ret.append((char) a[i]); 
            i++;
        }
        return ret;
    }
}
