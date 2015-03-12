// AsusDiscover.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"
#pragma comment(lib, "ws2_32.lib")
#include "..\Common\includes\InfosvrDefines.h"
#include "..\Common\includes\InfosvrExploit.h"
#define RECV_INFO_MAX 15

int getInfo(IBOX_COMM_PKT_HDR_EX* phdr_ex, SOCKET sock, SOCKADDR_IN* targetAddr, int timeout_ms, BOOL bVerbose, BOOL bSilent)
{
	IBOX_COMM_PKT_RES_EX responses[RECV_INFO_MAX];	// headers of responses
	memset(responses, 0, sizeof(responses));
	fd_set fdSet;
	TIMEVAL timVal;
	timVal.tv_sec = 0;
	timVal.tv_usec = timeout_ms*1000;

	char pdubuf_res[INFO_PDU_LENGTH];	// receive buffer
	IBOX_COMM_PKT_RES_EX *phdr_res	= (IBOX_COMM_PKT_RES_EX*)pdubuf_res;						// receive buffer header
	PKT_GET_INFO *ginfo				= (PKT_GET_INFO*)(pdubuf_res+sizeof(IBOX_COMM_PKT_RES));	// receive buffer body

	int uniqueResponses = 0;

	for (int i = 0; i < RECV_INFO_MAX; i++)
	{
		FD_ZERO(&fdSet);
		FD_SET(sock, &fdSet);
		int sss = select(NULL, &fdSet, NULL, NULL, &timVal);	// socket select status
		if (sss == SOCKET_ERROR)	// ERROR
		{
			char wsaErr[8];
			sprintf_s(wsaErr, sizeof(wsaErr), "%d", WSAGetLastError());
			printf_s("\ngetResponse(): Error checking SOCKET status.\tWSA error: %s\n", wsaErr);
			char system_cmd[80];
			sprintf_s(system_cmd, sizeof(system_cmd), "net helpmsg %s", wsaErr);
			system(system_cmd);

			closesocket(sock);
			WSACleanup();
			exit(EXIT_FAILURE);
		}
		else if (sss == NULL)	// TIMEOUT (No packets)
		{
			if (!bSilent) 
			{
				printf_s("\nThats all.\n");
			}
			break;	// do not wait other responses
		}
		// OK, packet available
		sss = sizeof(*targetAddr);
		int recvLen = recvfrom(sock, pdubuf_res, sizeof(pdubuf_res), 0, (SOCKADDR*)targetAddr, &sss);	// receive response
		if (recvLen == SOCKET_ERROR)
		{
			char wsaErr[8];
			sprintf_s(wsaErr, sizeof(wsaErr), "%d", WSAGetLastError());
			printf_s("\ngetResponse(): Failed to receive data through SOCKET.\tWSA error: %s\n", wsaErr);
			char system_cmd[80];
			sprintf_s(system_cmd, sizeof(system_cmd), "net helpmsg %s", wsaErr);
			system(system_cmd);

			closesocket(sock);
			WSACleanup();
			exit(EXIT_FAILURE);
		}

		if (phdr_res->ServiceID == NET_SERVICE_ID_IBOX_INFO && phdr_res->OpCode == NET_CMD_ID_GETINFO)
		{
			if (phdr_res->PacketType == NET_PACKET_TYPE_CMD)	// usually our broadcast packet
			{
				i--;	// to receive other RIGHT packet instead
				if (!bSilent) printf_s("%c\n", 253);	// received our broadcast packet
				continue;	// get next
			}
			else if (phdr_res->PacketType == NET_PACKET_TYPE_RES)	// response
			{
				{
					uniqueResponses++;

					if (!bSilent)
					{
						printf_s("#%d Response from %s:\n", uniqueResponses, inet_ntoa(targetAddr->sin_addr));

						printf_s("\n\tIPAddress: \t%s\n",				inet_ntoa(targetAddr->sin_addr));
						printf_s("\tPrinterInfo: \t%s\n",				ginfo->PrinterInfo);
						printf_s("\tSSID: \t\t%s\n",					ginfo->SSID);
						printf_s("\tNetMask: \t%s\n",					ginfo->NetMask);
						printf_s("\tProductID: \t%s\n",					ginfo->ProductID);
						printf_s("\tFirmwareVersion: \t%s\n",			ginfo->FirmwareVersion);
						printf_s("\tOperationMode: \t0x%.2x\t(%d)\n",	ginfo->OperationMode, ginfo->OperationMode);
						printf_s("\tMacAddress: \t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",	
							ginfo->MacAddress[0], 
							ginfo->MacAddress[1], 
							ginfo->MacAddress[2], 
							ginfo->MacAddress[3], 
							ginfo->MacAddress[4], 
							ginfo->MacAddress[5]);
						printf_s("\tRegulation: \t0x%.2x\t(%d)\n",		ginfo->Regulation, ginfo->Regulation);
					}

					if (!bSilent && bVerbose)
					{
						printf_s("\n\t[Verbose info]:\n");
						printf_s("phdr_res->ServiceID\t= 0x%.2x\t(%d)\n", phdr_res->ServiceID, phdr_res->ServiceID);
						printf_s("phdr_res->PacketType\t= 0x%.2x\t(%d)\n", phdr_res->PacketType, phdr_res->PacketType);
						printf_s("phdr_res->OpCode\t= 0x%.4x\t(%d)\n", phdr_res->OpCode, phdr_res->OpCode);
						printf_s("phdr_res->Info\t\t= 0x%.8x\t(%d)\n", phdr_res->Info, phdr_res->Info);
					}
				}
			}
			else
			{	// unknown packet type
				if (!bSilent) printf_s("%c", 15);
				continue;	// get next
			}
		}
		else
		{	// unknown service/cmd packet
			if (!bSilent) printf_s("%c", 15);
			continue;	// get next
		}
	}
	return uniqueResponses;
}

int _tmain(int argc, _TCHAR* argv[])
{
	int timeout_msec = 2000;
	BOOL bVerbose = FALSE;
	BOOL bSilent = FALSE;
	char *targetIP = "255.255.255.255";	// if target not specified - broadcast
	
	if (argc > 1)
	{
		targetIP = argv[1];
	}
	if (argc > 2)
	{
		for (int i = 2; i < argc; i++)
		{
			if (stricmp(argv[i], "VERBOSE") == 0)
			{
				bVerbose = TRUE;
			}
			else if (stricmp(argv[i], "SILENT") == 0)
			{
				bSilent = TRUE;
			}
			else
			{
				printf_s("Unrecognized option: '%s'\tIt will be ignored.\n", argv[i]);
			}
		}
	}
	
	//***	Setup socket and addresses	***//
	SOCKET sock = NULL;
	SOCKADDR_IN localAddr, targetAddr;
	setupNetworking(targetIP, &sock, &localAddr, &targetAddr);

	//***	Prepare packet & send	***//
	char pdubuf[INFO_PDU_LENGTH];	// send buffer
	memset(pdubuf, 0, sizeof(pdubuf));
	IBOX_COMM_PKT_HDR_EX *phdr_ex	= (IBOX_COMM_PKT_HDR_EX*)pdubuf;						// send buffer header
	phdr_ex->ServiceID	= NET_SERVICE_ID_IBOX_INFO;	// MUST be such
	phdr_ex->PacketType = NET_PACKET_TYPE_CMD;		// MUST be such
	phdr_ex->OpCode		= NET_CMD_ID_GETINFO;		// to get router info

	printf_s("Sending GETINFO request to %s...\t", inet_ntoa(targetAddr.sin_addr));
	int sentLen = sendto(sock, pdubuf, sizeof(pdubuf), 0, (SOCKADDR*)&targetAddr, sizeof(targetAddr));	// send cmd
	if (sentLen == SOCKET_ERROR)
	{
		printf_s("Failed to send data through SOCKET.\tWSA error: %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return 1;
	}
	printf_s("Request sent.\n");
	printf_s("Waiting responses on %s...\n", inet_ntoa(localAddr.sin_addr));

	int quantity = getInfo(phdr_ex, sock, &targetAddr, timeout_msec, bVerbose, bSilent);
	printf_s("Total %d responses.\n", quantity);
	
	//***	Exit program	***//
	if (closesocket(sock) == SOCKET_ERROR)
	{
		printf_s("Failed to close SOCKET.\tWSA error: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	WSACleanup();
	return 0;
}

