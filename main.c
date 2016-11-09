#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<inttypes.h>

#include "windivert.h"

#define MAXBUF 0xffff

int main() {
	HANDLE handle;
	WINDIVERT_ADDRESS addr;
	char packet[MAXBUF];
	UINT packetLen;


	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;

	char *data;
	UINT payload_len;

	handle = WinDivertOpen("tcp.DstPort == 80 or tcp.SrcPort ==80", WINDIVERT_LAYER_NETWORK, 0, 0);

	if (handle == INVALID_HANDLE_VALUE)
	{
		printf("error.\n");
		// Handle error
		exit(1);
	}

	// Main capture-modify-inject loop:
	while (TRUE)
	{
		//if (!WinDivertRecvEx(handle, packet, sizeof(packet), 0,&addr, &packetLen, NULL))
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packetLen))
		{
			// Handle recv error
			continue;
		}

		// Modify packet.

		WinDivertHelperParsePacket(packet, packetLen, &ip_header, &ipv6_header, &icmp_header, &icmpv6_header, &tcp_header, &udp_header, &data, &payload_len);

		//UINT8 *src_port = (UINT* *)&tcp_header->SrcPort;

		if (addr.Direction == 0 &&payload_len > 0 && data[0] == 0x47 && data[1] == 0x45 && data[2] == 0x54) {

			//UINT8 *str_location = strstr(data, "Accept-Encoding: gzip, deflate, sdch");
			UINT8 *str_location = strstr(data, "Accept-Encoding: ");
			if (str_location != NULL) {
				UINT8 *end_location = strstr(str_location, "\r\n");

				strcpy_s(str_location + 17, sizeof("deflate"), "deflate");

				str_location = str_location + 24;

				while (str_location != end_location) {
					strcpy_s(str_location, 2, " ");
					str_location = str_location + 1;
				}
				end_location[0] = 0x0d;

				WinDivertHelperCalcChecksums(packet, packetLen, NULL);
			}
		
		}

		if (addr.Direction == 1 && payload_len > 0) {
			UINT8 *str_location = strstr(data, "Michael");
			if (str_location != NULL) {
				strcpy_s(str_location,sizeof("gilbert"),"gilbert");
			}
			
			WinDivertHelperCalcChecksums(packet, packetLen, NULL);
		}

		if (!WinDivertSend(handle, packet, packetLen, &addr, NULL))
		{
			// Handle send error
			continue;
		}
	}


}