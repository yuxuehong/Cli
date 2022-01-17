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

extern struct vty *vty;

typedef struct sockaddr_in SOCKADDR_IN;
typedef int SOCKET;

T_VTYSH_CONN_CTX m_conn_ctx;

SInt32 vtysh_command_send_packet(T_VTYSH_CONN_CTX* ctx);
SOCKET vtysh_command_socket();


int vtysh_command_exec_func(struct cmd_element *ce, struct vty *vty, int argc, char **argv)
{
	T_VTYSH_COMMAND_ELE *cmd_ele; 
	UInt32 idx; 
	UInt32 arg_len = 0;
	char arg_data[1000];
	T_VTYSH_CONN_CTX *ictx;
	SInt32 i = 0;

	cmd_ele = (T_VTYSH_COMMAND_ELE *)ce;
	
	idx = cmd_ele->Idx;

	if(argc != cmd_ele->Argc)
	{

		vty_out(vty,"vtysh_command_exec_func: argc num is error! %d, %d \n", argc,  cmd_ele->Argc);
		return -1;
	}
	ictx = MY_CONTAINER_OF_CMD_ELE(ce, T_VTYSH_CONN_CTX,cmd_list, idx);//

	arg_data[0] = '\0';
	if(argc > 0)
	{
		strcpy(arg_data, argv[0]);
		arg_len += strlen(argv[0]) + 1;
		
		for(i = 1; i<argc; i++)
		{
			strcpy(arg_data, " ");
			strcpy(arg_data, argv[i]);
			arg_len +=  strlen(argv[i]) + 1;
		}
   		//printf("%d,%d,%s",idx, arg_len, arg_data);
		vtysh_send_exec_req(ictx, idx, arg_len, arg_data);
	}
	else
	{
		 m_conn_ctx.addr_update=1;
   		 vtysh_send_exec_req(ictx, idx, 0, NULL);
	}
	vtysh_command_state_to(VTYSH_WAIT_RESP);
	return 0;
}



SInt32 vtysh_send_init_req(T_VTYSH_CONN_CTX *ctx)
{
	T_VTYSH_MSG_HDR *msg_hdr = NULL;
	UInt32 len = 0;
	T_VTYSH_INIT_REQ *init_req = NULL;

	if(ctx == NULL)
	{
		return -1;
	}
	
	msg_hdr = (T_VTYSH_MSG_HDR *)ctx->sndBuf;	
	msg_hdr->sessNo = htonl(ctx->connSess);
	msg_hdr->msgID = htonl(VTYSH_INIT_REQ);
	msg_hdr->msgLen = htonl(sizeof(T_VTYSH_INIT_REQ));
	
	init_req = (T_VTYSH_INIT_REQ *)msg_hdr->data;
	init_req->sessNo = htonl(ctx->connSess);
	init_req->srcPort = htons(ctx->selfPort);
	init_req->dstPort = htons(ctx->dstPort);
	memcpy(init_req->dstIp, ctx->dstIp, 20);
	memcpy(init_req->srcIp, ctx->selfIp, 20);
	len += sizeof(T_VTYSH_INIT_REQ);
	ctx->sndBufLen = len + sizeof(T_VTYSH_MSG_HDR);
	
	vtysh_command_send_packet(ctx);
	return 0;
}


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
	cmd_ele->cmd_str[help_len] = '\0';

	ce = (struct cmd_element *)&(cmd_ele->Ele);
	ce->string = cmd_ele->cmd_str;
	ce->doc = cmd_ele->help_str;
	ce->func = vtysh_command_exec_func;
	cmd_install_element(SYS_VIEW_NODE, ce);
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


SInt32 vtysh_send_exec_req(T_VTYSH_CONN_CTX *ctx,UInt32 idx, UInt32 arg_len, char *arg_data)
{
	T_VTYSH_MSG_HDR *msg_hdr = NULL;
	//UInt32 len = 0;
	T_VTYSH_EXEC_REQ_HDR *exec_req = NULL;

	if(ctx == NULL)
	{
		return -1;
	}
	
	msg_hdr = (T_VTYSH_MSG_HDR *)ctx->sndBuf;	
	msg_hdr->sessNo = htonl(ctx->connSess);
	msg_hdr->msgID = htonl(VTYSH_EXEC_REQ);

	exec_req = (T_VTYSH_INIT_REQ *)msg_hdr->data;
	exec_req->Idx = htonl(idx);
	exec_req->ArgcLen = htonl(arg_len);
	if(arg_len > 0)
		memcpy(exec_req->data, arg_data, arg_len);
	ctx->sndBufLen = arg_len + sizeof(T_VTYSH_EXEC_REQ_HDR) + sizeof(T_VTYSH_MSG_HDR);

	vtysh_command_send_packet(ctx);
	return 0;
}


SInt32 vtysh_proc_exec_resp(T_VTYSH_CONN_CTX *ctx, UInt32 offset)
{
	T_VTYSH_MSG_HDR *exec_resp = NULL;
	UInt32 sessNo = 0;
	UInt32 msgId = 0;
	char *data_ptr;

	exec_resp = (T_VTYSH_MSG_HDR *)ctx->recBuf;
	sessNo = ntohl(exec_resp->sessNo);
	msgId = ntohl(exec_resp->msgID);
	
    UInt32 data_len=(ctx->recBufLen)-sizeof(T_VTYSH_MSG_HDR);
	data_ptr = (char *)exec_resp->data;
	if(data_ptr[data_len-1] != '\0')
	{
		data_ptr[data_len-1] = '\0';
	}

	printf("%s\n", data_ptr);
	return 0;
}


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
	msg_hdr->sessNo = htonl(ctx->connSess);
	msg_hdr->msgID = htonl(VTYSH_DISCONN_REQ);

	init_req = (T_VTYSH_INIT_REQ *)msg_hdr->data;
	init_req->sessNo = htonl(ctx->connSess);
	init_req->srcPort = htons(ctx->selfPort);
	init_req->dstPort = htonl(ctx->dstPort);
	memcpy(init_req->dstIp, ctx->dstIp, 20);
	memcpy(init_req->srcIp, ctx->selfIp, 20);
	len += sizeof(T_VTYSH_INIT_REQ);
	ctx->sndBufLen = len + sizeof(T_VTYSH_MSG_HDR);
	vtysh_command_send_packet(ctx);
	
	return 0;
}


UInt32 vtysh_command_get_rand()
{
	return (rand()%(1000000000)+1);
}


SInt32 vtysh_parse_comm_ind(T_VTYSH_CONN_CTX         *ctx)
{
	UInt32 msgId;
	UInt32 msgLen;
	UInt32 sessNum;
	SInt32 ret;
	UInt8 *ptr = (UInt8 *)ctx->recBuf;	
	T_VTYSH_MSG_HDR * msg_hdr = NULL;
	UInt32 offset = sizeof(T_VTYSH_MSG_HDR);
		
	msg_hdr = (T_VTYSH_MSG_HDR *)ptr;
	sessNum = ntohl(msg_hdr->sessNo);
	if(sessNum != ctx->connSess)
	{
		vty_out(vty,"sessNo error");
		return -1;
	}
	msgLen = ntohl(msg_hdr->msgLen);
	

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
		vtysh_command_state_to(VTYSH_WAIT_INPUT);
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
	int addr_len = sizeof(struct sockaddr_in);

	m_conn_ctx.cli_sock = -1;
	m_conn_ctx.cli_sock = vtysh_command_socket();

	ictx->recv_running = 1;	

	while(ictx->recv_running)
	{
		vtysh_command_wait_state(VTYSH_WAIT_RESP);

		len = recvfrom(ictx->cli_sock,ictx->recBuf, VTYSH_REC_BUFFER_SZ, 0, (struct sockaddr*)&server_addr, &addr_len);
		if(len == 0)
		{
			sleep(1);
		}
		else if(len < 0)
		{
			printf( "recvfrom failed!\n" );
		}
    	else
		{
			ictx->recBufLen = len;
			vtysh_command_state_to(VTYSH_WAIT_EXEC);
			vtysh_parse_comm_ind(ictx);
		}
	}
}




SInt32 vtysh_command_wait_state(UInt32 state)
{
	while(m_conn_ctx.waitState != state)
	{
		sleep(1);
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
	server_addr.sin_port = htons(ctx->dstPort);
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


int vtysh_sys_cmd_connect(struct cmd_element *ce, struct vty *v, int argc, char **argv)
{ 
	char arg_ip[20];
	unsigned short arg_port;
	arg_ip[0] = '\0';
	strcpy(arg_ip, argv[0]);
	arg_port = (unsigned short)atoi(argv[1]);
	
	strcpy(m_conn_ctx.dstIp, arg_ip);
	m_conn_ctx.dstPort = arg_port;
	
	vtysh_send_init_req(&m_conn_ctx);

	vtysh_command_state_to(VTYSH_WAIT_RESP);

	return 0;
}

int vtysh_sys_cmd_set(struct cmd_element *ce, struct vty *v, int argc, char **argv)
{
  unsigned short arg_port;
	arg_port = (unsigned short)atoi(argv[0]);
	m_conn_ctx.selfPort = arg_port;
	m_conn_ctx.addr_update = 1;
	
	return 0;
}


extern UInt32 main_is_running;
int vtysh_sys_cmd_exit(struct cmd_element *ce, struct vty *v, int argc, char **argv)
{
	main_is_running = 0;
	printf("Thank you for using, exitting...");
	return 0;
}


SInt32 vtysh_command_ins_sys()
{
	struct cmd_element *ce = NULL;
	
	ce = (struct cmd_element *)&(sys_cmd_connect);
	ce->string = "connect to IP PORT";
	ce->doc = "connect to a lte\r connect to a lte\r input the ip address of server:xxx.xxx.xxx.xxx\r input the port of server";
	ce->func = vtysh_sys_cmd_connect;
	cmd_install_element(SYS_VIEW_NODE, ce);

    ce = (struct cmd_element *)&(sys_cmd_exit);
	ce->string = "exit";
	ce->doc = "exit from client";
	ce->func = vtysh_sys_cmd_exit;
	cmd_install_element(SYS_VIEW_NODE, ce);


	ce = (struct cmd_element *)&(sys_cmd_set);
	ce->string = "set ip port IP PORT";
	ce->doc = "set listen port , default port(60001)";
	ce->func = vtysh_sys_cmd_set;
	cmd_install_element(SYS_VIEW_NODE, ce);

	return 0;
}



SInt32 vtysh_command_init()
{
	//char *def_ip = "10.109.9.31"; 
	memset(&m_conn_ctx, 0, sizeof(m_conn_ctx));

	m_conn_ctx.connSess = vtysh_command_get_rand();
	m_conn_ctx.pubFunc = vtysh_command_exec_func; 
	
	m_conn_ctx.waitState = VTYSH_WAIT_NONE;
	m_conn_ctx.sndBufLen = 0;
	m_conn_ctx.recBufLen = 0;

	//m_conn_ctx.selfPort = 60001;
	//memcpy(m_conn_ctx.selfIp, def_ip, strlen(def_ip) + 1);
	m_conn_ctx.addr_update = 1;

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


