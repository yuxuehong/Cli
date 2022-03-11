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
#include <stdbool.h>

#if 0
#define MY_CONTAIN_OF(ptr, type, mem)   
({\
		const typeof( ((type *)0)->mem ) *__mptr = (ptr);  \
		(type *)((char *)__mptr - &(((type *)0)->mem));   \

})
#endif

#define TRUE 1
#define FALSE 0
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


#define VTYSH_INIT_REQ       (0x20000001)
#define VTYSH_INIT_SUCC_RESP (0x20000002)

#define VTYSH_EXEC_REQ            (0x20000003)
#define VTYSH_EXEC_FAIL_RESP      (0x20000004)
#define VTYSH_EXEC_SUCC_RESP      (0x20000005)

#define VTYSH_REC_BUFFER_SZ   60000
#define VTYSH_SND_BUFFER_SZ   60000

#define VTYSH_CMD_MAX         3000

#define MAX_ARGV_NUM   4



/* ����id���� */
#define SHOW_UE_TOTAL_CQI_CMDID    (UInt32)0x10000003
#define SHOW_UE_TOTAL_DL_MCS_CMDID    (UInt32)0x10000004
#define SHOW_UE_TOTAL_UL_MCS_CMDID    (UInt32)0x10000005
#define SHOW_UE_TOTAL_UL_SINR_CMDID    (UInt32)0x10000006
#define SHOW_UE_TOTAL_ULSCH_CNT_CMDID    (UInt32)0x10000007
#define SHOW_UE_TOTAL_DLSCH_CNT_CMDID    (UInt32)0x10000008
#define SHOW_UE_TOTAL_DLRB_CNT_CMDID     (UInt32)0x10000009
#define SHOW_UE_TOTAL_ULRB_CNT_CMDID     (UInt32)0x1000000a
#define SHOW_UE_TOTAL_PHR_CMDID     (UInt32)0x1000000b


#define MAX_LAST_DATA_LEN   (UInt16)40

/* 1��������״̬�£��յ�����˵���ʱ���������
   2��cmd2�����������յ�cmd1����ʱack���������
   3���Ѿ��л�������С����ͼ�£�ͳһ���˲���ʾ */
#define CHECK_NEED_SHOW(msgRcvhdr) \
        do\
        {\
            if((m_conn_ctx.waitState == VTYSH_WAIT_INPUT) || (ntohl(msgRcvhdr->seqNo) != m_conn_ctx.seqNo) || (msgRcvhdr->cellIndex != cellIndex_g))\
            {\
                return 0;\
            }\
        }while(0);



typedef struct
{
    UInt16 lastUeIndex; /* ��һ��UeIndex */
    UInt8 ucPad[2]; 
}T_UeIndexLastData;

typedef struct{
	UInt32 msgID;
	UInt32 msgLen; /* ָ����Ϣ�峤�� */
	UInt32 seqNo;
	UInt8 cellIndex;
	UInt8 period;/* ��������ݲ������� */
	bool lastFlag;/* ������ָ�� */
    bool firstFlag;/* �ͻ���ָ�� */
	char LastData[MAX_LAST_DATA_LEN];/* ������ְ����õ� */
}T_VTYSH_MSG_HDR;

typedef enum{
    ARGV_TYPE_NULL = 0,
    ARGV_TYPE_TOTALNUM,
    ARGV_TYPE_DIGITAL,
    ARGV_TYPE_STRING,
}T_ArgvType;

typedef struct
{
    T_ArgvType ArgvType;    //��������
    unsigned char Arglength;//����data����
    char data[];
}T_argvInfo;


typedef struct{
	UInt32 Idx;
	UInt32 cmdId;
	UInt16 cmdLineLen;
	UInt16 cmdHelpLen;
	UInt32 Argc;
	T_ArgvType ArgType[MAX_ARGV_NUM];
	char data[];
}T_VTYSH_CMD_DESC_HDR;



typedef struct{
	UInt32 Idx;
	UInt32 datalen;/* data���� */
	char data[];/* ����������T_argvInfo */
}T_VTYSH_EXEC_REQ_HDR;



typedef struct{
	struct cmd_element Ele;
	SInt32 used;
	UInt32 Idx;
	UInt32 cmdId;
	UInt32 Argc;
	T_ArgvType ArgType[MAX_ARGV_NUM];
	char *cmd_str;
	char *help_str;
}T_VTYSH_COMMAND_ELE;

typedef struct
{
   char ip[20]; /* ������IP */
   unsigned char ServerGetPeirod;   /* ���������ͳ������ */
   unsigned char ClientTimeOut;     /* �ͻ��˲�ѯ��ʱʱ�� */
   unsigned char ucPad[2];
   int port;                /* ����˶˿ں� */
}T_GlobalConfig;


typedef struct{
	UInt32 seqNo;   /* ��������к� */
	UInt32 CurCmdIndex;/* ��ǰ�������������ڷְ������������� */
	UInt32 CurCmdId;/* ��ǰ�����id�����ڷְ�ʱȷ��lastdata�ṹ */
	T_GlobalConfig stGlobalConf;
	UInt32 sndBufLen;
	char   sndBuf[VTYSH_SND_BUFFER_SZ];
	UInt32 recBufLen;
	char   recBuf[VTYSH_REC_BUFFER_SZ];
	pthread_t recv_thread;
	UInt32 waitState;
	pthread_mutex_t state_mutex;
	SOCKET cli_sock;
	T_VTYSH_COMMAND_ELE cmd_list[VTYSH_CMD_MAX];
}T_VTYSH_CONN_CTX;


typedef enum{
	VTYSH_WAIT_NONE,
	VTYSH_INIT_SUCCESS,
	VTYSH_WAIT_INPUT,
	VTYSH_WAIT_RESP,
}T_VTYSH_WAIT_STATE;





int vtysh_command_exec_func(struct cmd_element *ce, struct vty *vty, int argc, char **argv);
SInt32 vtysh_proc_init_resp_fail(T_VTYSH_CONN_CTX *ctx, UInt32 offset);
SInt32 vtysh_install_command(T_VTYSH_CONN_CTX *ctx, UInt32 idx, UInt32 cmdId, UInt32 argc,T_ArgvType *ArgvType, 
                                     char *cmd_str, UInt32 cmd_len, char *help_str, UInt32 help_len);
SInt32 vtysh_proc_init_resp_succ(T_VTYSH_CONN_CTX *ctx, UInt32 offset);
SInt32 vtysh_send_exec_req(T_VTYSH_CONN_CTX *ctx,UInt32 idx, UInt32 cmdId, int argc, T_ArgvType *ArgType,char **argv);
SInt32 vtysh_proc_exec_resp(T_VTYSH_CONN_CTX *ctx, UInt32 offset);
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


