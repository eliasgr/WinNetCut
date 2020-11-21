using PacketDotNet;
using SharpPcap;
using SharpPcap.Npcap;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace WinNetCut
{
    public static class ARPExtensions
    {
        private static Dictionary<IPAddress, PhysicalAddress> clientList = new Dictionary<IPAddress, PhysicalAddress>();

        public static Dictionary<IPAddress, PhysicalAddress> Resolve(this ARP arp,NpcapDevice device,IPAddress destIP,IPAddress localIP,PhysicalAddress localMAC)
        {
            clientList.Clear();
            var request = BuildRequest(destIP, localMAC, localIP);
            string arpFilter = "arp ad ether dst " + localMAC.ToString();

            device.Open(DeviceMode.Normal, 20);
            device.Filter = arpFilter;
            var lastRequestTime = DateTime.FromBinary(0);
            var requestInterval = new TimeSpan(0, 0, 1);
            ArpPacket arpPacket = null;
            var timeout = DateTime.Now + arp.Timeout;

            while (DateTime.Now < timeout)
            {
                
                if (requestInterval<(DateTime.Now-lastRequestTime))
                {
                    device.SendPacket(request);
                    lastRequestTime = DateTime.Now;
                }

                var reply = device.GetNextPacket();
                if (reply==null)
                {
                    continue;
                }
                
                var packet = Packet.ParsePacket(reply.LinkLayerType, reply.Data);
                arpPacket = packet.Extract<ArpPacket>();

                if (arpPacket == null)
                {
                    continue;
                }

                if (arpPacket.SenderHardwareAddress.Equals(destIP))
                {
                    break;
                }
            }

            if (DateTime.Now >= timeout)
            {
                return null;
            }
            else
            {
                clientList.Add(arpPacket.SenderProtocolAddress, arpPacket.SenderHardwareAddress);
                return clientList;
            }
            
            

        }

        private static Packet BuildRequest(IPAddress destIP, PhysicalAddress localMAC, IPAddress localIP)
        {
            var ethernetPacket = new EthernetPacket(localMAC, PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), EthernetType.Arp);
            var arpPacket = new ArpPacket(ArpOperation.Request, PhysicalAddress.Parse("00-00-00-00-00-00"), destIP, localMAC, localIP);
            ethernetPacket.PayloadPacket = arpPacket;
            return ethernetPacket;
        }
    }
}
