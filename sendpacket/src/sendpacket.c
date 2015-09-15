/*
 ============================================================================
 Name        : sendpacket.c
 Author      : davidfdzp
 Version     : 0.2
 Copyright   : Based on WinPcap and http://www.binarytides.com/raw-sockets-packets-with-winpcap/
 Description : send raw IP packets in Windows with Cygwin
 ============================================================================
 */

#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

#include "headers.h"

#include <stdbool.h>

#define PKT_SIZE 65536

int main(int argc, char **argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char *name;
	int inum;
	int j=0;
	int pkt_size = 100;

	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int8_t packet[PKT_SIZE];
	int i;

	struct in_addr dstip;
	struct in_addr srcip;

	IPAddr DstIP;
	IPAddr SrcIP;

	ULONG MacAddr[2];
	ULONG PhyAddrLen = ETHER_ADDR_LEN;

	pcap_addr_t *a;

	char straddr[INET6_ADDRSTRLEN];
	/** subnet mask */
	bpf_u_int32 maskp;
	/** ip */
	bpf_u_int32 netp;
	bool pcap_lookupnet_failed = false;

	int gatewayip;

	struct ether_header *eth_hdr;
	struct ip *ip_hdr;

	SrcIP=0;

	eth_hdr = (struct ether_header *)packet;
	ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

	/* Check the validity of the command line */
	if (argc < 3)
	{
		/* Retrieve the device list */
			if(pcap_findalldevs(&alldevs, errbuf) == -1)
			{
				fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
				exit(1);
			}

			/* Print the list */
			for(d=alldevs; d; d=d->next)
			{
				printf("%d. %s", ++j, d->name);
				if (d->description)
					printf(" (%s) ", d->description);
				else
					printf(" (No description available) ");
				for(a=d->addresses; a!=NULL; a=a->next) {
					if(a->addr->sa_family == AF_INET){
						printf(" %s", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					}else if(a->addr->sa_family == AF_INET6){
						printf(" %s", inet_ntop(AF_INET6, &(((struct sockaddr_in6*)a->addr)->sin6_addr), straddr, sizeof(straddr)));
					}
				}
				printf("\n");
			}

			if(j==0)
			{
				printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
				return -1;
			}

			printf("Enter the interface number (1-%d):",j);
			scanf("%d", &inum);
			printf("Selected interface %d\n", inum);

			/* Check if the user specified a valid adapter */
			if(inum < 1 || inum > j)
			{
				printf("\nAdapter number out of range.\n");

				/* Free the device list */
				pcap_freealldevs(alldevs);
				return -1;
			}

			/* Jump to the selected adapter */
			for(d=alldevs, j=0; j< inum-1 ;d=d->next, j++);

			name = d->name;
			// Get first IPv4 address configured in the interface as source IP
			for(a=d->addresses; a!=NULL; a=a->next) {
				if(a->addr->sa_family == AF_INET){
					printf(" Selected %s as interface source address\n", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					memcpy(&srcip,&((struct sockaddr_in*)a->addr)->sin_addr,sizeof(srcip));
					break;
				}
			}

	}else{
		name = argv[2];
		/** ask pcap for the network address and mask of the device, needed afterwards */
		if(pcap_lookupnet(name,&netp,&maskp,errbuf)<0){
			fprintf(stderr,"Error getting IPv4 network address and mask of device %s: %s\n", name, errbuf);
			pcap_lookupnet_failed = true;
#ifdef PCAP_NETMASK_UNKNOWN
			netp = maskp = PCAP_NETMASK_UNKNOWN;
#else
			netp = maskp = 0;
#endif
		}
		if(!pcap_lookupnet_failed){
			memcpy(&srcip,&netp,sizeof(srcip));
		}
	}

	printf("Using adapter %s with address %s\n", name, inet_ntoa(srcip));
	memcpy(&SrcIP,&srcip,sizeof(IPAddr));

	if(argc < 2){
		/* Get default GW destination IP associated to selected interface IP as destination IP */
		GetGateway(srcip, straddr, &gatewayip);
		memcpy(&dstip,&gatewayip,sizeof(dstip));
	}else{
		/* Use command line provided destination IP */
		if (inet_aton(argv[1], &dstip) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
	}

	printf("Sending packet to %s\n", inet_ntoa(dstip));
	memcpy(&DstIP,&dstip,sizeof(IPAddr));

	/* Open the adapter */
	if ((fp = pcap_open_live(name,		// name of the device
							 65536,			// portion of the packet to capture. It doesn't matter in this case
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
		return 2;
	}

	/* Get MAC address corresponding to packet destination IP address (ARP on IPv4),
	 * link with -liphlpapi and use function SendArp */
	SendARP(DstIP, SrcIP, MacAddr, &PhyAddrLen);
	if(PhyAddrLen){
		BYTE *bMacAddr = (BYTE *)&MacAddr;
		for(i=0;i<(int)PhyAddrLen;i++){
			eth_hdr->dst[i] = (u_int8_t)bMacAddr[i];
		}
	}else{	// If ARP did not found destination MAC address, use default gw IP associated MAC address
		/* Get default GW destination IP associated to selected interface IP as destination IP */
		GetGateway(srcip, straddr, &gatewayip);
		memcpy(&DstIP,&gatewayip,sizeof(IPAddr));
		SendARP(DstIP, SrcIP, MacAddr, &PhyAddrLen);
		if(PhyAddrLen){
			BYTE *bMacAddr = (BYTE *)&MacAddr;
			for(i=0;i<(int)PhyAddrLen;i++){
				eth_hdr->dst[i] = (u_int8_t)bMacAddr[i];
			}
		}else{
			fprintf(stderr,"Error getting default gateway MAC address\n");
		}
	}

	printf("Dst MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
			eth_hdr->dst[0], eth_hdr->dst[1],
			eth_hdr->dst[2], eth_hdr->dst[3],
			eth_hdr->dst[4], eth_hdr->dst[5]);

	/** Get adapter HW address */
	GetMacAddress(eth_hdr->src, SrcIP);
	printf("Src MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
			eth_hdr->src[0],eth_hdr->src[1],
			eth_hdr->src[2],eth_hdr->src[3],
			eth_hdr->src[4],eth_hdr->src[5]);

	/* set ethertype to IP */
	eth_hdr->type=htons(0x0800);

	/* Next comes the IP header */
	ip_hdr->ip_v = 4;
	ip_hdr->ip_hl = sizeof(struct ip)/4; // 5 in double words (a double word are 4 bytes)
	ip_hdr->ip_tos = IPTOS_DSCP_EF;
	ip_hdr->ip_len = htons(pkt_size-sizeof(struct ether_header));
	ip_hdr->ip_id = htons(2);
	ip_hdr->ip_off = htons(IP_DF); ///< fragment offset field (don't fragment)
	ip_hdr->ip_ttl = 255;
	ip_hdr->ip_p = IPPROTO_NONE;	///< protocol
	memcpy(&ip_hdr->ip_src,&srcip,sizeof(struct in_addr));
	memcpy(&ip_hdr->ip_dst,&dstip,sizeof(struct in_addr));
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = in_checksum((unsigned short*)ip_hdr, sizeof(struct ip));

	/* Fill the rest of the packet */
	for(i=sizeof(struct ether_header)+sizeof(struct ip);i<pkt_size;i++)
	{
		packet[i]= (u_char)i;
	}

	/* Send down the packet */
	if (pcap_sendpacket(fp,	// Adapter
		packet,				// buffer with the packet
		pkt_size			// size
		) != 0)
	{
		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
		return 3;
	}

	pcap_close(fp);

	return EXIT_SUCCESS;
}
