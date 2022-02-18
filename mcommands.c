#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <math.h>
#include "mcommands.h"
#include <arpa/inet.h>

//#include <winsock2.h>
//#pragma comment(lib,"ws2_32.lib")
extern UInt32 main_is_running;
extern struct vty *vty;
extern SOCKET sock_g;
extern unsigned char cellIndex_g;
extern T_GlobalConfig g_GlobalInfo;
typedef struct sockaddr_in SOCKADDR_IN;
typedef int SOCKET;

T_VTYSH_CONN_CTX m_conn_ctx;

SInt32 vtysh_command_send_packet(T_VTYSH_CONN_CTX* ctx);
SOCKET vtysh_command_socket();


int vtysh_command_exec_func(struct cmd_element *ce, struct vty *vty, int argc, char **argv)
{
	T_VTYSH_COMMAND_ELE *cmd_ele; 
	UInt32 idx; 
	T_VTYSH_CONN_CTX *ictx;
	cmd_ele = (T_VTYSH_COMMAND_ELE *)ce;
	
	idx = cmd_ele->Idx;

	if(argc != cmd_ele->Argc)
	{

		vty_out(vty,"vtysh_command_exec_func: argc num is error! %d, %d \n", argc,  cmd_ele->Argc);
		return -1;
	}
	ictx = MY_CONTAINER_OF_CMD_ELE(ce, T_VTYSH_CONN_CTX,cmd_list, idx);//

	vtysh_send_exec_req(ictx, idx, argc, argv);
	vtysh_command_state_to(VTYSH_WAIT_RESP);
	return 0;
}


/*
SInt32 vtysh_send_init_req(T_VTYSH_CONN_CTX *ctx)
{
	T_VTYSH_MSG_HDR *msg_hdr = NULL;
	UInt32 len = 0;

	if(ctx == NULL)
	{
		return -1;
	}
	
	msg_hdr = (T_VTYSH_MSG_HDR *)ctx->sndBuf;	
	msg_hdr->msgID = htonl(VTYSH_INIT_REQ);
	msg_hdr->msgLen = htonl(sizeof(T_VTYSH_INIT_REQ));
	
	len += sizeof(T_VTYSH_INIT_REQ);
	ctx->sndBufLen = len + sizeof(T_VTYSH_MSG_HDR);
	
	vtysh_command_send_packet(ctx);
	return 0;
}*/


SInt32 vtysh_proc_init_resp_fail(T_VTYSH_CONN_CTX *ctx, UInt32 offset)
{
	UInt8 *ptr = (UInt8*)(ctx->recBuf+offset);
	printf("%s", ptr);
	return 0;
}


SInt32 vtysh_install_command(T_VTYSH_CONN_CTX *ctx, UInt32 idx, UInt32 argc, 
                                     char *cmd_str, UInt32 cmd_len, char *help_str, UInt32 help_len)
{
	SInt32 ret = 0;
	T_VTYSH_COMMAND_ELE *cmd_ele;
	struct cmd_element *ce;
	
	if(idx >= VTYSH_CMD_MAX)
	{
		return -1;
	}
	
	if(ctx->cmd_list[idx].used)
	{
		return -1;
	}

	cmd_ele = &(ctx->cmd_list[idx]);
	cmd_ele->used = 1;
	cmd_ele->Argc = argc;
	cmd_ele->Idx = idx;
	cmd_ele->cmd_str = (char*)malloc(cmd_len+2);
	memcpy(cmd_ele->cmd_str, cmd_str, cmd_len);
	cmd_ele->cmd_str[cmd_len] = '\0';
	cmd_ele->help_str = (char *)malloc(help_len+2);
	memcpy(cmd_ele->help_str, help_str, help_len);
	cmd_ele->help_str[help_len] = '\0';

	ce = (struct cmd_element *)&(cmd_ele->Ele);
	ce->string = cmd_ele->cmd_str;
	ce->doc = cmd_ele->help_str;
	ce->func = vtysh_command_exec_func;
	cmd_install_element(CELL_NODE, ce);
	return ret;
}


SInt32 vtysh_proc_init_resp_succ(T_VTYSH_CONN_CTX *ctx, UInt32 offset)
{
	UInt8 *ptr = (UInt8*)(ctx->recBuf+offset);
	UInt32 left_byte = ctx->recBufLen - offset;
	T_VTYSH_CMD_DESC_HDR *cmd_desc = NULL;
	UInt16 cmdstr_len;
	UInt16 helpstr_len;
	UInt32 mIdx;
	UInt32 mArgc;

	

	while(left_byte > 0)
	{	
		cmd_desc = (T_VTYSH_CMD_DESC_HDR *)ptr;
		if(left_byte <= sizeof(T_VTYSH_CMD_DESC_HDR))
		{
			break;
		}
		
		cmdstr_len = ntohs(cmd_desc->cmdLineLen);
		helpstr_len = ntohs(cmd_desc->cmdHelpLen);
		mIdx = ntohl(cmd_desc->Idx);
		mArgc = ntohl(cmd_desc->Argc);
		
		if(left_byte < cmdstr_len + helpstr_len + sizeof(T_VTYSH_CMD_DESC_HDR))
		{
			break;
		}
		vtysh_install_command(ctx, mIdx, mArgc, (char*)cmd_desc->data,cmdstr_len,    
                                                (char*)(cmd_desc->data+cmdstr_len),helpstr_len);

		left_byte -= cmdstr_len + helpstr_len + sizeof(T_VTYSH_CMD_DESC_HDR);
		ptr += cmdstr_len + helpstr_len + sizeof(T_VTYSH_CMD_DESC_HDR);
	}
	return 0;
}



SInt32 vtysh_send_exec_req(T_VTYSH_CONN_CTX *ctx,UInt32 idx, int argc, char **argv)
{
	T_VTYSH_MSG_HDR *msg_hdr = NULL;
	//UInt32 len = 0;
	T_VTYSH_EXEC_REQ_HDR *exec_req = NULL;
	unsigned char uArgcNum = argc;
	unsigned short i = 0;
	UInt32 dataLen = 0;
	T_argvInfo *argvData = NULL;
	unsigned long long offset = OFFSET(T_argvInfo, data);

	if(ctx == NULL)
	{
		return -1;
	}

	m_conn_ctx.seqNo++;//每个命令发送需要更新seqno;
	msg_hdr = (T_VTYSH_MSG_HDR *)ctx->sndBuf;	
	msg_hdr->msgID = htonl(VTYSH_EXEC_REQ);
    msg_hdr->seqNo = htonl(m_conn_ctx.seqNo);

	exec_req = (T_VTYSH_EXEC_REQ_HDR *)((char *)msg_hdr + sizeof(T_VTYSH_MSG_HDR));
	exec_req->Idx = htonl(idx);
	argvData = (T_argvInfo *)(exec_req->data);
	
    /* 第一个tlv指明有多少个参数 */
    argvData->Arglength = sizeof(unsigned char);
    memcpy(argvData->data, &uArgcNum, argvData->Arglength);
    dataLen = offset + argvData->Arglength;
    for(i = 0; i<argc; i++)
	{
		argvData = (T_argvInfo *)((unsigned char *)argvData + offset + argvData->Arglength);
        argvData->Arglength =  strlen(argv[i]) + 1;
        memcpy(argvData->data, argv[i], argvData->Arglength);
        dataLen += offset + argvData->Arglength;
	}
 
	exec_req->datalen = htonl(dataLen);
	ctx->sndBufLen = dataLen + sizeof(T_VTYSH_EXEC_REQ_HDR) + sizeof(T_VTYSH_MSG_HDR);

	vtysh_command_send_packet(ctx);
	return 0;
}


SInt32 vtysh_proc_exec_resp(T_VTYSH_CONN_CTX *ctx, UInt32 offset)
{
	T_VTYSH_MSG_HDR *exec_resp = NULL;
	UInt32 seqNo = 0;
	char *data_ptr;

	exec_resp = (T_VTYSH_MSG_HDR *)ctx->recBuf;
	seqNo = ntohl(exec_resp->seqNo);
	
	if((m_conn_ctx.waitState == VTYSH_WAIT_INPUT) || (seqNo != m_conn_ctx.seqNo) || (exec_resp->cellIndex != cellIndex_g))
	{
	    /* 1、待输入状态下，收到服务端的延时包，需过滤
	    2、cmd2请求后可能先收到cmd1的延时ack包，需过滤
	    3、已经切换到其他小区视图下，统一过滤不显示 */
        return 0;
	}
    UInt32 data_len=(ctx->recBufLen)-sizeof(T_VTYSH_MSG_HDR);
	data_ptr = (char *)exec_resp + sizeof(T_VTYSH_MSG_HDR);
	if(data_ptr[data_len] != '\0')
	{
		data_ptr[data_len] = '\0';
	}
    if(m_conn_ctx.waitState == VTYSH_WAIT_INPUT)
    {
        return 0;
    }
    else
    {
	    printf("%s\n", data_ptr);    
	    vtysh_command_state_to(VTYSH_WAIT_INPUT);
	}
	return 0;
}

/*
SInt32 vtysh_send_disconn_req(T_VTYSH_CONN_CTX *ctx)
{
	T_VTYSH_MSG_HDR *msg_hdr = NULL;
	UInt32 len = 0;
	T_VTYSH_INIT_REQ *init_req = NULL;

	if(ctx == NULL)
	{
		return -1;
	}
	
	msg_hdr = (T_VTYSH_MSG_HDR *)ctx->sndBuf;	
	msg_hdr->msgID = htonl(VTYSH_DISCONN_REQ);

	init_req = (T_VTYSH_INIT_REQ *)((char *)msg_hdr + sizeof(T_VTYSH_MSG_HDR));
	init_req->srcPort = htons(ctx->selfPort);
	init_req->dstPort = htonl(ctx->dstPort);
	memcpy(init_req->dstIp, ctx->dstIp, 20);
	memcpy(init_req->srcIp, ctx->selfIp, 20);
	len += sizeof(T_VTYSH_INIT_REQ);
	ctx->sndBufLen = len + sizeof(T_VTYSH_MSG_HDR);
	vtysh_command_send_packet(ctx);
	
	return 0;
}*/


UInt32 vtysh_command_get_rand()
{
	return (rand()%(1000000000)+1);
}


SInt32 vtysh_parse_comm_ind(T_VTYSH_CONN_CTX         *ctx)
{
	UInt32 msgId;
	UInt32 msgLen;
	SInt32 ret;
	UInt8 *ptr = (UInt8 *)ctx->recBuf;	
	T_VTYSH_MSG_HDR * msg_hdr = NULL;
	UInt32 offset = sizeof(T_VTYSH_MSG_HDR);
		
	msg_hdr = (T_VTYSH_MSG_HDR *)ptr;
	msgLen = ntohl(msg_hdr->msgLen);
	if(msgLen + offset > sizeof(ctx->recBuf))
	{
        printf("recv msg len out of range, msgLen = %d.\n", msgLen);
        return -1;
	}
	msgId = ntohl(msg_hdr->msgID);
	switch(msgId)
	{
	case VTYSH_INIT_FAIL_RESP:
		ret = vtysh_proc_init_resp_fail(ctx, offset);
		vtysh_command_state_to(VTYSH_WAIT_INPUT);
		break;
	case VTYSH_INIT_SUCC_RESP:
		ret = vtysh_proc_init_resp_succ(ctx, offset);
		if(ret == 0)
		{
			vtysh_command_state_to(VTYSH_WAIT_INPUT);
		}
		else
		{
			vtysh_command_state_to(VTYSH_WAIT_RESP);
		}
		break;
		
	case VTYSH_EXEC_RESP:
		ret = vtysh_proc_exec_resp(ctx, offset);
		
		break;
	default:
		break;	
	}
	

	return ret;
}


void *vtysh_comm_recv_loop(void *ctx)
{
	T_VTYSH_CONN_CTX *ictx = (T_VTYSH_CONN_CTX*)ctx;
	SOCKADDR_IN server_addr;
	int len = 0;
	int addr_len = 0;
    struct timeval tv;
    tv.tv_sec = g_GlobalInfo.ClientTimeOut;
    tv.tv_usec = 0;
    if (setsockopt(ictx->cli_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        printf("socket option  SO_RCVTIMEO not support\n");
        return NULL;
    }
    m_conn_ctx.recv_running = 1;

	while(m_conn_ctx.recv_running)
	{
		vtysh_command_wait_state(VTYSH_WAIT_RESP);//不能加，如果加了，后面只要有一个回复延迟，就会导致后续命令seqno都对不上，进而导致都没法显示需要信息
        
		len = recvfrom(ictx->cli_sock,ictx->recBuf, VTYSH_REC_BUFFER_SZ, 0, (struct sockaddr*)&server_addr, &addr_len);
		if(len == 0)
		{
			sleep(1);
		}
		else if(len < 0)
		{
		    /* 超时主线程不等 */  
		    if(ictx->waitState == VTYSH_WAIT_INPUT)
		    {
                continue;
		    }
		    printf( "cmd execute timeout!\n" );
		    vtysh_command_state_to(VTYSH_WAIT_INPUT);
		}
    	else
		{
			ictx->recBufLen = len;
			vtysh_parse_comm_ind(ictx);
		}
	}

	return NULL;
}




SInt32 vtysh_command_wait_state(UInt32 state)
{
	while(m_conn_ctx.waitState != state)
	{
		//sleep(1);
	}
	return 0;
}


SInt32 vtysh_command_state_to(UInt32 state)
{
	if(m_conn_ctx.waitState == state)
		return 0;
	else
	{
		pthread_mutex_lock(&(m_conn_ctx.state_mutex));
		m_conn_ctx.waitState = state;
		pthread_mutex_unlock(&(m_conn_ctx.state_mutex));
	}
	return 0;
}

/*
UInt32 winsock_is_initted = 0;
SOCKET vtysh_command_socket()
{
	SOCKET sock;
	WSADATA wsadata;
	int ret;
	unsigned long ul = 1;

	if(!winsock_is_initted)
	{
		if(WSAStartup(MAKEWORD(2,2), &wsadata)!= 0)
		{
			printf("init winsock2 fail\n");
			return -1;
		}
		winsock_is_initted = 1;
	}
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0)
	{
		printf("create socket fail\n");
		return sock;
	}

	ret = ioctlsocket(sock, FIONBIO, &ul);
	if(ret == SOCKET_ERROR)
	{
		printf("ioctlsocket FIONBIO failed! \n");
	}
	return sock;
}
*/


SOCKET vtysh_command_socket()
{
	SOCKET sock;
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock < 0)
	{
		printf("create socket fail\n");
		return sock;
	}
	return sock;
}




SInt32 vtysh_command_send_packet(T_VTYSH_CONN_CTX* ctx)
{
	SOCKADDR_IN server_addr;

	if(ctx->cli_sock < 0)
	{
		printf("client socket init failed! \n");
		return -1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(ctx->dstPort + cellIndex_g);
    server_addr.sin_addr.s_addr = inet_addr(ctx->dstIp);

	sendto(ctx->cli_sock, ctx->sndBuf, ctx->sndBufLen, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
	return 0;
}

struct cmd_element sys_cmd_connect;
struct cmd_element sys_cmd_exit;
struct cmd_element sys_cmd_set;

void vtysh_sys_switch_node(struct vty *v, UInt32 node)
{
	v->node = node;
}


int vtysh_sys_cmd_cell_select(struct cmd_element *ce, struct vty *v, int argc, char **argv)
{ 
	char *str = argv[0];
	
	if((*str < '0') || (*str > '2'))
	{
        printf ("%% Invalid cellIndex, range(0~2).\n");
        return 0;
	}
	cellIndex_g = (unsigned short)atoi(argv[0]);;
	vty->node = CELL_NODE;
	return 0;
}

int vtysh_cmd_quit(struct cmd_element *ce, struct vty *v, int argc, char **argv)
{

	main_is_running = 0;
	//vtysh_command_destroy();
	return 0;
}


extern UInt32 main_is_running;
int vtysh_cell_cmd_exit(struct cmd_element *ce, struct vty *v, int argc, char **argv)
{
	//main_is_running = 0;
	vty->node = SYS_VIEW_NODE;
	//printf("Thank you for using, exitting...");
	return 0;
}


SInt32 vtysh_command_ins_sys()
{
	struct cmd_element *ce = NULL;

	ce = (struct cmd_element *)&(sys_cmd_connect);
	ce->string = "cell Index";
	//ce->doc = "choose a cell\r index of the cell(0;1;2)";
	ce->doc = "choose a cell\r index(0,1,2)";
	ce->func = vtysh_sys_cmd_cell_select;
	cmd_install_element(SYS_VIEW_NODE, ce);


    ce = (struct cmd_element *)&(sys_cmd_exit);
	ce->string = "exit";
	ce->doc = "exit to homepage";
	ce->func = vtysh_cell_cmd_exit;
	cmd_install_element(CELL_NODE, ce);


	ce = (struct cmd_element *)&(sys_cmd_set);
	ce->string = "quit";
	ce->doc = "end the program";
	ce->func = vtysh_cmd_quit;
	cmd_install_element(SYS_VIEW_NODE, ce);
	cmd_install_element(CELL_NODE, ce);

	return 0;
}



SInt32 vtysh_command_init()
{
//	m_conn_ctx.pubFunc = vtysh_command_exec_func; //没用
	
	m_conn_ctx.sndBufLen = 0;
	m_conn_ctx.recBufLen = 0;
    m_conn_ctx.seqNo = 0;

	pthread_mutex_init(&(m_conn_ctx.state_mutex), NULL);
 	pthread_mutex_unlock(&(m_conn_ctx.state_mutex));
	pthread_create(&(m_conn_ctx.recv_thread), NULL, vtysh_comm_recv_loop, &m_conn_ctx);

	return 0;
}


SInt32 vtysh_command_destroy()
{
	void *result;
	m_conn_ctx.recv_running = 0;
	pthread_join(m_conn_ctx.recv_thread, &result);
	return 0;
}


