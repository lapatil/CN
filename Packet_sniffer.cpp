#include <iostream>
#include <string>
#include <crafter.h>

using namespace std;
using namespace Crafter;

void PacketHandler(Packet* sniff_packet, void* user) 
{
	int ch;
	int FIN,SYN,RST,PSH,ACK,URG;

	RawLayer* raw_payload = sniff_packet->GetLayer<RawLayer>();
	
	
	if(raw_payload) 
	{
		
		cout << "[+] --------------------------PBMJ5233-------------------------------- [+]" << endl;
		cout<< "\n ";
		TCP* tcp_layer = sniff_packet->GetLayer<TCP>();
		IP* ip_layer = sniff_packet->GetLayer<IP>();
		
		
		do
		{
		
			cout<<"\n -------------------------------MENU------------------------------";
			cout<<"\n | 1. Print IP address information of sniffed Packet              |";
			cout<<"\n | 2. Print Port address information of sniffed Packet            |";
			cout<<"\n | 3. Print Packet Identifier information of sniffed Packet       |";
			cout<<"\n | 4. Print Packet size information of sniffed Packet             |";
			cout<<"\n | 5. Print TCP Flags of sniffed Packet                           |";
			cout<<"\n | 6. sniff next packet                                           |";
			cout<<"\n -------------------------------MENU------------------------------";
		
			cout<<"\n Enter your choice :";
			cin>>ch;
			cout<<"\n -----------------------------------------------------------------";
			
			switch(ch)
			{

				case 1:
					cout << "\n  Source IP     : "<<ip_layer->GetSourceIP()<<endl;
					cout << "\n  Destination IP: "<<ip_layer->GetDestinationIP()<<endl; 
					break;
				case 2:
					cout << "\n  Source Port      : "<<tcp_layer->GetSrcPort()<<endl;
					cout << "\n  Destination Port : "<<tcp_layer->GetDstPort()<<endl;			
					break;
				case 3:
					cout << "\n Sequece Number         : "<<tcp_layer->GetSeqNumber()<<endl;
					cout << "\n Acknowledgement Number : "<<tcp_layer->GetAckNumber()<<endl;
					break;
				case 4:
					cout << "\n Window Size      : "<<tcp_layer-> GetWindowsSize() <<endl;
					cout << "\n Check-sum        : "<<tcp_layer->GetCheckSum()<<endl;
					break;
				case 5:
					FIN=int(tcp_layer->GetFIN());
					SYN=int(tcp_layer->GetSYN());
					RST=int(tcp_layer->GetRST());
					PSH=int(tcp_layer->GetPSH());
					ACK=int(tcp_layer->GetACK());
					URG=int(tcp_layer->GetURG());
				
					cout << "\n -----TCP-Flags-----"<<endl;
					cout << "\n FIN               : "<<FIN<<endl;
					cout << "\n SYN               : "<<(SYN/2)<<endl;
					cout << "\n RST		   : "<<(RST/4)<<endl;
					cout << "\n PSH		   : "<<(PSH/8)<<endl;
					cout << "\n ACK		   : "<<(PSH/16)<<endl; 
					cout << "\n URG		   : "<<(PSH/32)<<endl;
					break;
			}
	
		}while(ch!=6);
		cout<<"\n ";
	}
}


int main() 
{		
	while(1)
	{
		string iface = "eth0";
		Sniffer sniff("tcp",iface,PacketHandler);

		sniff.Capture(1);
	}	
		
	return 0;
}
