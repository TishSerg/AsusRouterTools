#pragma once

//Packet Type Section
#define NET_SERVICE_ID_BASE	        (10)
#define NET_SERVICE_ID_LPT_EMU	    (NET_SERVICE_ID_BASE + 1)
#define NET_SERVICE_ID_IBOX_INFO	(NET_SERVICE_ID_BASE + 2)

//Packet Type Section
#define NET_PACKET_TYPE_BASE	    (20)
#define NET_PACKET_TYPE_CMD	        (NET_PACKET_TYPE_BASE + 1)
#define NET_PACKET_TYPE_RES	        (NET_PACKET_TYPE_BASE + 2)

//Command ID Section
enum  NET_CMD_ID
{                               // Decimal      Hexadecimal
	NET_CMD_ID_BASE = 30,       //  30              0x1E
	NET_CMD_ID_GETINFO,         //  31					0x1F
	NET_CMD_ID_GETINFO_EX,      //  32              0x20
	NET_CMD_ID_GETINFO_SITES,   //  33              0x21
	NET_CMD_ID_SETINFO,         //  34              0x22
	NET_CMD_ID_SETSYSTEM,       //  35              0x23
	NET_CMD_ID_GETINFO_PROF,    //  36              0x24
	NET_CMD_ID_SETINFO_PROF,    //  37              0x25
    NET_CMD_ID_CHECK_PASS,      //  38              0x26
//#ifdef BTN_SETUP
	NET_CMD_ID_SETKEY_EX,	    //  39		0x27
	NET_CMD_ID_QUICKGW_EX,	    //  40 		0x28
	NET_CMD_ID_EZPROBE,			//  41		0x29
//#endif
	NET_CMD_ID_MANU_BASE=50,    //  50				0x32
	NET_CMD_ID_MANU_CMD,	    //  51					0x33
	NET_CMD_ID_GETINFO_MANU,    //  52              0x34
	NET_CMD_ID_GETINFO_EX2,     //  53              0x35
	NET_CMD_ID_MAXIMUM
};

#pragma pack(1)
//Packet Header Structure
typedef struct iboxPKTRes
{
	BYTE		ServiceID;
	BYTE		PacketType;
	WORD		OpCode;
	DWORD 		Info; // Or Transaction ID
} IBOX_COMM_PKT_RES;

typedef struct iboxPKTEx
{
	BYTE		ServiceID;
	BYTE		PacketType;
	WORD		OpCode;
	DWORD 		Info; // Or Transaction ID
	BYTE		MacAddress[6];
	BYTE		Password[32];   //NULL terminated string, string length:1~31, cannot be NULL string
} IBOX_COMM_PKT_HDR_EX;

typedef struct iboxPKTExRes
{
	BYTE		ServiceID;
	BYTE		PacketType;
	WORD		OpCode;
	DWORD 		Info; // Or Transaction ID
	BYTE		MacAddress[6];
} IBOX_COMM_PKT_RES_EX;

//Extended Fields Definition
typedef struct PktGetInfo
{
  	BYTE PrinterInfo[128];
	BYTE SSID[32];
  	BYTE NetMask[32];
  	BYTE ProductID[32];
  	BYTE FirmwareVersion[16];
  	BYTE OperationMode; 
  	BYTE MacAddress[6]; 
  	BYTE Regulation;
} PKT_GET_INFO;

typedef struct iboxPKTCmd
{
	WORD		len;
	BYTE		cmd[420];	// max command size (but, will be truncated to MAXSYSCMD size)
} PKT_SYSCMD;		// total 422 bytes

typedef struct iboxPKTCmdRes
{
	WORD		len;
	BYTE		res[420];	// max response size
} PKT_SYSCMD_RES;	// total 422 bytes
#pragma pack()