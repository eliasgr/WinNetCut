using PacketDotNet;
using SharpPcap;
using SharpPcap.Npcap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace WinNetCut
{
    public static class Helper
    {
        private static NpcapDevice device;
        private static NpcapDeviceList deviceList = NpcapDeviceList.Instance;


        public static async Task GetAllAsync(string interfaceFriendlyName)
        {
            IPAddress myIpAddress = GetIPAddress(interfaceFriendlyName);
            await SendArpRequestAsync(myIpAddress);
        }

        public static async Task SendArpRequestAsync(IPAddress ipAddress)
        {
            await Task.Run(() =>
            {
                for (int i = 0; i <= 255; i++)
                {
                    var arpRequest = new ArpPacket(
                        operation: ArpOperation.Request,
                        targetHardwareAddress: PhysicalAddress.Parse("00-00-00-00-00-00"),
                        targetProtocolAddress: IPAddress.Parse(GetRootIp(ipAddress) + i),
                        senderHardwareAddress: device.MacAddress, senderProtocolAddress: ipAddress);

                    var ethernetPacket = new EthernetPacket(
                        sourceHardwareAddress: device.MacAddress,
                        destinationHardwareAddress: PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"),
                        ethernetType: EthernetType.Arp)
                    {
                        PayloadPacket = arpRequest
                    };
                    device.SendPacket(ethernetPacket);
                }
            });
        }

        public static async Task<Dictionary<IPAddress, PhysicalAddress>> GetClients(IPAddress myIPAddress)
        {

            device.Filter = "arp";
            Dictionary<IPAddress, PhysicalAddress> clientList = null;
            RawCapture rawCapture = null;
            await Task.Run(() =>
            {
                try
                {
                    device.StartCapture();
                    while ((rawCapture = device.GetNextPacket()) != null)
                    {
                        var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
                        var arpPacket = packet.Extract<ArpPacket>();
                        if (arpPacket.SenderProtocolAddress.ToString() != "0.0.0.0" && AreCompatibleIPs(arpPacket.SenderProtocolAddress, myIPAddress))
                        {
                            clientList.Add(arpPacket.SenderProtocolAddress, arpPacket.SenderHardwareAddress);
                        }
                    }
                }
                catch (Exception)
                {

                    throw;
                }
            });
            return clientList;
        }

        public static List<string> GetDevices()
        {

            var devices = new List<string>();

            foreach (var device in deviceList)
            {
                if (device.Interface.FriendlyName != null)
                {
                    devices.Add(device.Interface.FriendlyName);

                }
            }

            devices.Sort();
            return devices;

        }


        private static bool AreCompatibleIPs(IPAddress ip1, IPAddress ip2)
        {
            return GetRootIp(ip1) == GetRootIp(ip2);
        }

        private static string GetRootIp(IPAddress ipAddress)
        {
            var ipString = ipAddress.ToString();
            return ipString.Substring(0, ipString.LastIndexOf(".") + 1);
        }

        public static NpcapDevice GetSelectedDevice(string interfaceFriendlyName)
        {
            foreach (NpcapDevice item in deviceList)
            {
                if (item.Interface.FriendlyName == null)
                {
                    continue;
                }
                if (item.Interface.FriendlyName.Equals(interfaceFriendlyName))
                {
                    device = item;
                    break;
                }

            }
            return device;
        }

        public static IPAddress GetIPAddress(string interfaceFriendlyName)
        {
            InitDevice();

            deviceList.Refresh();
            device = GetSelectedDevice(interfaceFriendlyName);
            device.Open(DeviceMode.Promiscuous, 1000);
            return device.Addresses[1].Addr.ipAddress;

        }

        private static void InitDevice()
        {
            if (device != null)
            {
                try
                {
                    device.StopCapture();
                    device.Close();
                }
                catch (Exception)
                {

                    throw;
                }
            }
        }

        //private IPAddress GetGetwayIP(string friendlyName)
        //{

        //}
        private static string GetMACAddress(PhysicalAddress physicalAddress)
        {
            try
            {
                string MACString = "";
                for (int i = 0; i < 5; i++)
                {
                    MACString += physicalAddress.GetAddressBytes()[i].ToString("X2") + ":";

                }
                return MACString.Substring(0, MACString.Length - 1);
            }
            catch (Exception)
            {

                throw;
            }
        }

        //private PhysicalAddress GetGetwayMAC(string friendlyName)
        //{

        //}
    }
}
