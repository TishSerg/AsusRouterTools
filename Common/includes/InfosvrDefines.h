#define PORT_LOCAL	9999
#define PORT_TARGET 9999

#define INFO_PDU_LENGTH		512		// UDP pkt data size
#define MAXINFOSVRCMD		238		// infosvr crash-safe cmd len
#define MAXSYSCMD			256		// infosvr truncate cmd to this len
#define SYSCMDBUF_MAX		420		// data buffer size in UDP pkt
#define SYSCMDBUF_RES_MAX	420		// data buffer size in UDP pkt

#define RECV_MAX 3	// max packets to receive (3 max responses)
