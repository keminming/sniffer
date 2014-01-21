#include<Winsock2.h>
#include "sniffer.h"
#include <conio.h>
#include <pcap.h>
#include <queue>
#include <fstream>

void dispatcher_handler(u_char * user, const struct pcap_pkthdr * header, const u_char * packet)
{
	parameter* p = (parameter*)user;

	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const u_char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	u_short dport = ntohs(tcp->th_dport);
	u_short sport = ntohs(tcp->th_sport);   

	if(p->port != dport && p->port != sport)
	{
		//printf("drop");
		return;
	}

	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		//return;
	}

	/*4 elememnt group hash*/
	u_long src = (u_long)ip->ip_src.s_addr;
	u_long dst = (u_long)ip->ip_dst.s_addr;
	u_long ldport = (u_long)dport | 0xffffff;
	u_long lsport = (u_long)sport | 0xffffff;
	u_long key = src | dst | ldport | lsport;

	payload = (const u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	int payload_len = header->len - (SIZE_ETHERNET + size_ip + size_tcp);

	if(p->session_map.find(key) == p->session_map.end())
	{
		session *s = new session;
		s->sport = sport;
		s->dport = dport;
		p->session_map[key] = s;
	}

	packet_info* p_info = new packet_info;
	p_info->payload = new char[1024*100];
	memcpy(p_info->payload,payload,payload_len);
	p_info->payload_len = payload_len;
	p_info->seq = tcp->th_seq;
	p_info->flag = tcp->th_flags;
	p_info->ack = tcp->th_ack;

	u_long packet_id = p_info->seq | p_info->ack & (p_info->flag | 0xffffffff) | p_info->payload_len;

	if(p->session_map[key]->seqs.find(packet_id) == p->session_map[key]->seqs.end())
	{	
		p->session_map[key]->seqs.insert(packet_id);
		p->session_map[key]->packet_queue.push_back(p_info);
	}
	
}

vector<packet_info*> reconstruct_tcp_flow(vector<packet_info*> packet_queue)
{
	vector<packet_info*> output_queue;
	u_long expect_sequence;
	int state;

	for(int i = 0; i < packet_queue.size();i++)
	{
		if(packet_queue[i]->flag == TH_SYN)
			if(packet_queue[i]->ack == 0)
			{
				expect_sequence = packet_queue[i]->seq + 1;
				output_queue.push_back(packet_queue[i]);
				packet_queue.erase(packet_queue.begin() + i);
			}			
	}

	for(int i = 0; i < packet_queue.size();i++)
	{
		if(packet_queue[i]->flag == TH_SYN)
			if(packet_queue[i]->ack == 1)
			{
				output_queue.push_back(packet_queue[i]);
				packet_queue.erase(packet_queue.begin() + i);
			}	
	}

	for(int i = 0; i < packet_queue.size();i++)
	{
		if(packet_queue[i]->flag == TH_ACK)
			if(packet_queue[i]->ack == 1 && packet_queue[i]->seq == expect_sequence)
			{
				output_queue.push_back(packet_queue[i]);
				packet_queue.erase(packet_queue.begin() + i);
			}	
	}

	state = SRC;
	bool stop = false;
	while(1)
	{
		if(stop)
		{
			break;
		}

		if(state == SRC)
		{
			for(int i = 0; i < packet_queue.size();i++)
			{
				if(packet_queue[i]->seq == expect_sequence && packet_queue[i]->flag != TH_FIN)
				{	
					output_queue.push_back(packet_queue[i]);
					expect_sequence = packet_queue[i]->seq + packet_queue[i]->payload_len;
					packet_queue.erase(packet_queue.begin() + i);
					state = DST;
					break;
				}

				if(packet_queue[i]->seq == expect_sequence && packet_queue[i]->flag == TH_FIN)
				{
					output_queue.push_back(packet_queue[i]);
					expect_sequence = packet_queue[i]->seq + 1;
					packet_queue.erase(packet_queue.begin() + i);
					stop = true;
				}
			}
		}

		if(state == DST)
		{
			for(int i = 0; i < packet_queue.size();i++)
			{
				if(packet_queue[i]->ack == expect_sequence && packet_queue[i]->flag != TH_FIN)
				{
					output_queue.push_back(packet_queue[i]);
					packet_queue.erase(packet_queue.begin() + i);
					state = SRC;
					break;
				}
			}
		}
	}
					
	for(int i = 0; i < packet_queue.size();i++)
	{
		if(packet_queue[i]->ack == expect_sequence)
		{	
			output_queue.push_back(packet_queue[i]);
			packet_queue.erase(packet_queue.begin() + i);
		}
	}

	for(int i = 0; i < packet_queue.size();i++)
	{
		if(packet_queue[i]->flag == TH_FIN && packet_queue[i]->seq != expect_sequence - 1)
		{	
			output_queue.push_back(packet_queue[i]);
			expect_sequence = packet_queue[i]->seq + 1;
			packet_queue.erase(packet_queue.begin() + i);

		}
	}

	for(int i = 0; i < packet_queue.size();i++)
	{
		if(packet_queue[i]->seq == expect_sequence)
		{
			output_queue.push_back(packet_queue[i]);
			packet_queue.erase(packet_queue.begin() + i);
		}
	}

	return output_queue;
}


void show_sessions(ofstream& of, char* buff,int offset,int port)
{
	printf("------------------------------------session--------------------------------------\n");
	of<<"\n------------------------------------------session---------------------------------------------\n";
	for(int k = 0; k < offset; k++)
	{
		if(isascii(buff[k]))
		{
			printf("%c",buff[k]);
			of<<buff[k];
		}
		else
		{
			printf("%x",buff[k]);
			of<<"0x"<<std::hex<<(int)buff[k];
		}
	}
}


int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	

	if(argc != 3){

		printf("Usage: sniffer [80|23|21] filename.\n");
		return -1;

	}

	int port_filter = atoi(argv[1]);
	
	/* Open the capture file */	
	fp = pcap_open_offline(argv[2],errbuf);

	if(fp == NULL)
	{
	    printf("Can't open pcap file error = %s.\n",errbuf);
		//getch();
		return -1;
	}

	parameter* p = new parameter;
	p->port = atoi(argv[1]);

	// read and dispatch packets until EOF is reached
	if(pcap_loop(fp, -1, dispatcher_handler, (u_char*)p) != 0)
	{
		printf("Read packet error.\n");
		return -1;
	}

	
	ofstream of;

	switch(p->port)
	{
	case 80:
		of.open("C:\\Users\\frank\\Desktop\\http.txt");
		break;
	case 21:
		of.open("C:\\Users\\frank\\Desktop\\ftp.txt");
		break;
	case 23:
		of.open("C:\\Users\\frank\\Desktop\\telnet.txt");
		break;
	}


	for(auto i = p->session_map.begin(); i != p->session_map.end(); i++)
	{
		session* s = i->second;
		if(s->sport == port_filter || s->dport == port_filter)
		{
			char* buff = new char[1024*100];
			int offset = 0;
			vector<packet_info*> ordered_queue = s->packet_queue;
			//vector<packet_info*> ordered_queue = reconstruct_tcp_flow(s->packet_queue);
			for(int j = 0; j < ordered_queue.size();j++)
			{
				packet_info* p_info = ordered_queue[j];
				memcpy(buff + offset, p_info->payload, p_info->payload_len);
				offset += p_info->payload_len;
			}

			show_sessions(of,buff,offset,p->port);
		}
	}

	of.flush();
	of.close();
	_getch();
	return 0;
}