#ifndef _LTE_MCOMMAND_H_
#define _LTE_MCOMMAND_H_
//#include <winsock2.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "command.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#if 0
#define MY_CONTAIN_OF(ptr, type, mem)   
({\
		const typeof( ((type *)0)->mem ) *__mptr = (ptr);  \
		(type *)((char *)__mptr - &(((type *)0)->mem));   \

})
#endif


#define MY_CONTAINER_OF_CMD_ELE(ptr, type, mem, idx)  ((type *)((char*)ptr - (char*)&(((type *)0)->mem[idx])))
#define OFFSET(TYPE, MEM)   ((unsigned long long) &((TYPE*)0)->MEM) 



typedef unsigned int    UInt32;
typedef unsigned short  UInt16;
typedef unsigned char   UInt8;
typedef int    			SInt32;
typedef short  			SInt16;
typedef char   			SInt8;

typedef struct sockaddr_in SOCKADDR_IN;
typedef int SOCKET;


#define VTYSH_INIT_REQ       (0x20200001)
#define VTYSH_INIT_FAIL_RESP (0x20200002)
#define VTYSH_INIT_SUCC_RESP (0x20200003)

#define VTYSH_EXEC_REQ       (0x20200004)
#define VTYSH_EXEC_RESP      (0x20200005)
#define VTYSH_DISCONN_REQ    (0x20200006)

#define VTYSH_REC_BUFFER_SZ   20000
#define VTYSH_SND_BUFFER_SZ   20000

#define VTYSH_CMD_MAX         3000


#ifdef HOST_IS_BIG_ENDINESS
#define HTONL(val) (val)
#define HTONS(val) (val)
#define NTOHL(val) (val)
#define NTOHS(val) (val)
#else
#define HTONL(val) (((val&0xff0000)>>24) | ((val&0xff)<<24) | ((val&0xff00)<<8) |((val&0xff0000)>>8))
#define HTONS(val) (((val&0xff)<<8) |((val&0xff00)>>8))
#define NTOHL(val) HTONL(val)
#define NTOHS(val) HTONS(val)
#endif



typedef struct{
	UInt32 msgID;
	UInt32 msgLen;
	UInt32 seqNo;
}T_VTYSH_MSG_HDR;


typedef struct{
	UInt32 sessNo;
	char srcIp[20];
	UInt16 srcPort;
	char dstIp[20];
	UInt16 dstPort;
}T_VTYSH_INIT_REQ;


typedef struct{
	UInt32 Idx;
	UInt16 cmdLineLen;
	UInt16 cmdHelpLen;
	UInt32 Argc;
	char data[];
}T_VTYSH_CMD_DESC_HDR;



typedef struct{
	UInt32 Idx;
	UInt32 datalen;/* data长度 */
	char data[];
}T_VTYSH_EXEC_REQ_HDR;


typedef struct{
	UInt32 idx;
	UInt32 DataLen;
	char data[];
}T_VTYSH_EXEC_RESP_HDR;



typedef struct{
	struct cmd_element Ele;
	SInt32 used;
	UInt32 Idx;
	UInt32 Argc;
	char *cmd_str;
	char *help_str;
}T_VTYSH_COMMAND_ELE;



typedef struct{
	SInt32 connState;
	UInt32 connSess;
	UInt32 seqNo;
	char selfIp[20];
	UInt16 selfPort;
	char dstIp[20];
	UInt16 dstPort;

	UInt32 addr_update;
	UInt32 sndBufLen;
	char   sndBuf[VTYSH_SND_BUFFER_SZ];
	UInt32 recBufLen;
	char   recBuf[VTYSH_REC_BUFFER_SZ];


	pthread_t recv_thread;
	UInt32 recv_running;

	UInt32 waitState;
	UInt32 waitTime;     // 鍗曚綅 100ms
	UInt32 waitTimeout;  // 
	pthread_mutex_t state_mutex;

	SOCKET cli_sock;
	void  *pubFunc;
	T_VTYSH_COMMAND_ELE cmd_list[VTYSH_CMD_MAX];
	
}T_VTYSH_CONN_CTX;


typedef enum{
	VTYSH_WAIT_NONE,
	VTYSH_WAIT_INIT,
	VTYSH_WAIT_INPUT,
	VTYSH_WAIT_RESP,
	VTYSH_WAIT_EXEC,
}T_VTYSH_WAIT_STATE;

typedef struct
{
    unsigned char Arglength;//参数长度
    char data[];
}T_argvInfo;


int vtysh_command_exec_func(struct cmd_element *ce, struct vty *vty, int argc, char **argv);
SInt32 vtysh_send_init_req(T_VTYSH_CONN_CTX *ctx);
SInt32 vtysh_proc_init_resp_fail(T_VTYSH_CONN_CTX *ctx, UInt32 offset);
SInt32 vtysh_install_command(T_VTYSH_CONN_CTX *ctx, UInt32 idx, UInt32 argc, 
                                     char *cmd_str, UInt32 cmd_len, char *help_str, UInt32 help_len);
SInt32 vtysh_proc_init_resp_succ(T_VTYSH_CONN_CTX *ctx, UInt32 offset);
SInt32 vtysh_send_exec_req(T_VTYSH_CONN_CTX *ctx,UInt32 idx, int argc, char **argv);
SInt32 vtysh_proc_exec_resp(T_VTYSH_CONN_CTX *ctx, UInt32 offset);
SInt32 vtysh_send_disconn_req(T_VTYSH_CONN_CTX *ctx);
UInt32 vtysh_command_get_rand();
SInt32 vtysh_parse_comm_ind(T_VTYSH_CONN_CTX         *ctx);
void *vtysh_comm_recv_loop(void *ctx);
SInt32 vtysh_command_wait_state(UInt32 state);
SInt32 vtysh_command_state_to(UInt32 state);
SOCKET vtysh_command_socket();
SInt32 vtysh_command_send_packet(T_VTYSH_CONN_CTX* ctx);
void vtysh_sys_switch_node(struct vty *v, UInt32 node);
int vtysh_sys_cmd_cell_select(struct cmd_element *ce, struct vty *v, int argc, char **argv);
int vtysh_cmd_quit(struct cmd_element *ce, struct vty *v, int argc, char **argv);
int vtysh_cell_cmd_exit(struct cmd_element *ce, struct vty *v, int argc, char **argv);
SInt32 vtysh_command_ins_sys();
SInt32 vtysh_command_init();
SInt32 vtysh_command_destroy();

#endif


