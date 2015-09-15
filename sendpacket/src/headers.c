/*
 * headers.c
 *
 */

#include "headers.h"

void GetMacAddress(unsigned char *mac, IPAddr destip){
	IPAddr srcip=0;
	ULONG MacAddr[2];
	ULONG PhyAddrLen = ETHER_ADDR_LEN;
	int i;

	// Now print the MAC address also
	SendARP(destip, srcip, MacAddr, &PhyAddrLen);
	if(PhyAddrLen){
		BYTE *bMacAddr = (BYTE *) & MacAddr;
		for(i = 0; i < (int) PhyAddrLen; i++)
			mac[i] = (char)bMacAddr[i];
	}
}

void GetGateway(struct in_addr ip , char *sgatewayip , int *gatewayip) {
    char pAdapterInfo[5000];
    PIP_ADAPTER_INFO  AdapterInfo;
    ULONG OutBufLen = sizeof(pAdapterInfo) ;

    GetAdaptersInfo((PIP_ADAPTER_INFO) pAdapterInfo, &OutBufLen);
    for(AdapterInfo = (PIP_ADAPTER_INFO)pAdapterInfo; AdapterInfo ; AdapterInfo = AdapterInfo->Next) {
        if(ip.s_addr == inet_addr(AdapterInfo->IpAddressList.IpAddress.String))
     strcpy(sgatewayip , AdapterInfo->GatewayList.IpAddress.String);
    }
    *gatewayip = inet_addr(sgatewayip);
}

/*
	General Networking Functions
	Checksum function - used to calculate the IP header and TCP header checksums
*/
unsigned short in_checksum(unsigned short *ptr,int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(SHORT)~sum;

	return(answer);
}
