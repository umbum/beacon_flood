#include <iostream>
#include <tins/tins.h>
#include <unistd.h>

using namespace Tins;
using namespace std;

bool callback(const PDU &pdu) {
    // Find the IP layer
    const IP &ip = pdu.rfind_pdu<IP>(); 
    // Find the TCP layer
    const TCP &tcp = pdu.rfind_pdu<TCP>(); 
    cout << ip.src_addr() << ':' << tcp.sport() << " -> " 
         << ip.dst_addr() << ':' << tcp.dport() << endl;
    return true;
}

void setBeacon(Dot11Beacon& beacon, std::string bssid, std::string ssid){
  beacon.addr1(Dot11::BROADCAST);
  // Our current channel is 8
  beacon.addr2(bssid);
  
  beacon.addr3(beacon.addr2());

  beacon.ds_parameter_set(8);
  // This is our list of supported rates:
  beacon.supported_rates({ 1.0f, 5.5f, 11.0f });
  // Encryption: we'll say we use WPA2-psk encryption
  beacon.rsn_information(RSNInformation::wpa2_psk());

  beacon.ssid(ssid);
}

int main() {
  // Sniffer("ens33").sniff_loop(callback);
  PacketSender sender;
	Dot11Beacon beacon1;
	Dot11Beacon beacon2;
	Dot11Beacon beacon3;
	Dot11Beacon beacon4;

  setBeacon(beacon1, "00:01:02:03:04:05", "아무도");
  setBeacon(beacon2, "00:01:22:03:04:05", "나를");
  setBeacon(beacon3, "00:01:32:03:04:05", "막을 순");
  setBeacon(beacon4, "00:01:42:03:04:05", "없으셈ㅋㅋ");
  RadioTap tap1;
  RadioTap tap2;
  RadioTap tap3;
  RadioTap tap4;
  tap1.inner_pdu(beacon1);
  tap2.inner_pdu(beacon2);
  tap3.inner_pdu(beacon3);
  tap4.inner_pdu(beacon4);

  NetworkInterface iface("mon0");
  while (true) {
    sender.send(tap1, iface);
    sender.send(tap2, iface);
    sender.send(tap3, iface);
    sender.send(tap4, iface);
    usleep(100000);
  }
  
}
