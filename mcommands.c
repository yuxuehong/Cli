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
#include <termios.h>


//#include <winsock2.h>
//#pragma comment(lib,"ws2_32.lib")
extern UInt32 main_is_running;
extern struct vty *vty;
extern unsigned char cellIndex_g;
extern T_GlobalConfig g_GlobalInfo;
extern struct termios old;
typedef struct sockaddr_in SOCKADDR_IN;
typedef int SOCKET;

T_VTYSH_CONN_CTX m_conn_ctx;

SInt32 vtysh_command_send_packet(T_VTYSH_CONN_CTX* ctx);
SOCKET vtysh_command_socket();


int vtysh_command_exec_func(struct cmd_element *ce, struct vty *vty, int argc, char **argv)
{
    SInt32 ret = -1;
	T_VTYSH_COMMAND_ELE *cmd_ele; 
	UInt32 idx; 
	T_VTYSH_CONN_CTX *ictx;
	cmd_ele = (T_VTYSH_COMMAND_ELE *)ce;
	
	idx = cmd_ele->Idx;

	if(argc != cmd_ele->Argc)
	{

		vty_out(vty,"vtysh_command_exec_func: argc num is error! Current Argc:%d, Register Argc:%d \n", argc,  cmd_ele->Argc);
		return -1;
	}
	ictx = MY_CONTAINER_OF_CMD_ELE(ce, T_VTYSH_CONN_CTX,cmd_list, idx);//

	ret = vtysh_send_exec_req(ictx, idx, argc, cmd_ele->ArgType, argv);
	if(ret == 0)
	{
	    vtysh_command_state_to(VTYSH_WAIT_RESP);
	}
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
bool checkRepNeedShow()
{
    UInt32 seqNo = 0;
    
    T_VTYSH_MSG_HDR * msgRcvhdr = NULL;
    msgRcvhdr = (T_VTYSH_MSG_HDR *)m_conn_ctx.recBuf;
    seqNo = ntohl(msgRcvhdr->seqNo);

    if((m_conn_ctx.waitState == VTYSH_WAIT_INPUT) || (seqNo != m_conn_ctx.seqNo) || (msgRcvhdr->cellIndex != cellIndex_g))
    {
        /* 1、待输入状态下，收到服务端的延时包，需过滤
        2、cmd2请求后可能先收到cmd1的延时ack包，需过滤
        3、已经切换到其他小区视图下，统一过滤不显示 */
        return FALSE;
    }

    return TRUE;
}

SInt32 vtysh_proc_exec_resp_fail(T_VTYSH_CONN_CTX *ctx, UInt32 offset)
{
    T_VTYSH_MSG_HDR * msgRcvhdr = NULL;
    msgRcvhdr = (T_VTYSH_MSG_HDR *)m_conn_ctx.recBuf;
    CHECKNEEDSHOW(msgRcvhdr);
	UInt8 *ptr = (UInt8*)(ctx->recBuf+offset);
	printf("%s", ptr);
	return 0;
}


SInt32 vtysh_install_command(T_VTYSH_CONN_CTX *ctx, UInt32 idx, UInt32 argc, T_ArgvType *ArgvType,
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
	memcpy(cmd_ele->ArgType, ArgvType, sizeof(cmd_ele->ArgType));
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
    T_ArgvType ArgvType[MAX_ARGV_NUM] = {0};
	UInt8 i = 0;

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
		for(i = 0; i < mArgc; i++)
		{
		    ArgvType[i] = ntohl(cmd_desc->ArgType[i]);
		}
		if(left_byte < cmdstr_len + helpstr_len + sizeof(T_VTYSH_CMD_DESC_HDR))
		{
			break;
		}
		vtysh_install_command(ctx, mIdx, mArgc, ArgvType, (char*)cmd_desc->data,cmdstr_len,    
                                                (char*)(cmd_desc->data+cmdstr_len),helpstr_len);

		left_byte -= cmdstr_len + helpstr_len + sizeof(T_VTYSH_CMD_DESC_HDR);
		ptr += cmdstr_len + helpstr_len + sizeof(T_VTYSH_CMD_DESC_HDR);
	}
	return 0;
}

void PackageExecMsgHead(T_VTYSH_MSG_HDR *msg_hdr, UInt32 msgLen, bool firstFlag)
{
    msg_hdr = (T_VTYSH_MSG_HDR *)m_conn_ctx.sndBuf;
	msg_hdr->msgID = htonl(VTYSH_EXEC_REQ);
    msg_hdr->seqNo = htonl(m_conn_ctx.seqNo);
    msg_hdr->msgLen = htonl(msgLen);
    msg_hdr->period = m_conn_ctx.stGlobalConf.ServerGetPeirod;
    msg_hdr->t_LastData.firstFlag = firstFlag;
    
    return;
}

bool checkArgvVaild(T_ArgvType type, char *str)
{
    if(ARGV_TYPE_DIGITAL == type)
    {
        if ((strspn(str, "0123456789") != strlen(str)) || ((strlen(str) > 1) && (str[0] == '0')))
        {
            printf("parameter is invaild.\n");
            return FALSE;
        }
    }

    return TRUE;
}


bool PackageExecInfo(T_VTYSH_CONN_CTX *ctx, bool firstFlag, int argc, T_ArgvType *ArgType, char **argv)
{
    T_VTYSH_MSG_HDR *msg_hdr = NULL;
    T_VTYSH_EXEC_REQ_HDR *exec_req = NULL;
    T_argvInfo *argvData = NULL;
    unsigned short i = 0;
    UInt32 dataLen = 0;
    bool checkRet = TRUE;
    unsigned long long offset = OFFSET(T_argvInfo, data);

    msg_hdr = (T_VTYSH_MSG_HDR *)ctx->sndBuf;	
	
    exec_req = (T_VTYSH_EXEC_REQ_HDR *)((char *)msg_hdr + sizeof(T_VTYSH_MSG_HDR));
    exec_req->Idx = htonl(m_conn_ctx.CurCmdIdx);
    argvData = (T_argvInfo *)(exec_req->data);
        
    /* 第一个tlv指明有多少个参数 */
    argvData->ArgvType = htonl(ARGV_TYPE_TOTALNUM);
	argvData->Arglength = sizeof(unsigned char);	
    memcpy(argvData->data, &argc, argvData->Arglength);
    dataLen = offset + argvData->Arglength;
	
    for(i = 0; i < argc; i++)
    {	
		if(TRUE == firstFlag)
        {
            checkRet &= checkArgvVaild(ArgType[i], argv[i]);
            if(FALSE == checkRet)
            {
                return FALSE;
            }
        }
        argvData = (T_argvInfo *)((unsigned char *)argvData + offset + argvData->Arglength);
        argvData->ArgvType = htonl(ArgType[i]);
		argvData->Arglength = strlen(argv[i]) + 1; 
        memcpy(argvData->data, argv[i], argvData->Arglength);		
        dataLen += offset + argvData->Arglength;
    }
 
    exec_req->datalen = htonl(dataLen);
    ctx->sndBufLen = dataLen + sizeof(T_VTYSH_EXEC_REQ_HDR) + sizeof(T_VTYSH_MSG_HDR);
    PackageExecMsgHead(msg_hdr, dataLen + sizeof(T_VTYSH_EXEC_REQ_HDR), firstFlag);
    vtysh_command_send_packet(ctx);

    return TRUE;
}

SInt32 vtysh_send_exec_req(T_VTYSH_CONN_CTX *ctx,UInt32 idx, int argc, T_ArgvType *ArgType,char **argv)
{
    bool Ret = FALSE;
	if(ctx == NULL)
	{
		return -1;
	}

	m_conn_ctx.seqNo++;//每个命令刚开始发送需要更新seqno;
    m_conn_ctx.CurCmdIdx = idx;/* 保存当前命令idx以备后续分包使用 */
    memset(m_conn_ctx.sndBuf, 0, sizeof(m_conn_ctx.sndBuf));
    Ret = PackageExecInfo(ctx, TRUE, argc, ArgType, argv);
    if(FALSE == Ret)
    {
        return -1;
    }
	return 0;
}



void changeMode(int mode)
{
    struct termios new;
    new = old;
   //new.c_lflag &= ~(ICANON | ISIG);
    new.c_lflag &= ~(ICANON);
    new.c_cc[VTIME] = 0;
    new.c_cc[VMIN] = 1;
    if(mode == 0){
        new.c_lflag &= ~ECHO;               //不显示输入的值
        tcsetattr(0, TCSANOW, &new);        //输入之后立即执行，不需要按回车键
    }
    if(mode == 1){
        tcsetattr(0, TCSADRAIN, &old);	    //还原设置
    }
}


/* 目前参数只支持UeIndex */
void send_req_server(T_VTYSH_CONN_CTX *ctx, T_VTYSH_MSG_HDR *RecvHdr, UInt8 uArgcNum)
{
    char *argv[1] = {NULL};
    char argvTmp[10] = {0};
    T_ArgvType ArgType[MAX_ARGV_NUM] = {0};
	UInt16 UeIndex = ntohs(RecvHdr->t_LastData.lastUeIndex);

    snprintf(argvTmp, 10, "%u", UeIndex);
    argv[0] = argvTmp;
    ArgType[0] = ARGV_TYPE_DIGITAL;


	PackageExecInfo(ctx, FALSE, uArgcNum, ArgType, argv);

}

int waitToSendNextReq()
{
        int c;       
        changeMode(0);
        while(((m_conn_ctx.waitState != VTYSH_WAIT_INPUT)) && ((c = getchar()) != EOF))
        {
            if(c == '\n')
            {                         
                return 1;
            }
            else if (c == 'q')
            {
                vtysh_command_state_to(VTYSH_WAIT_INPUT);                
                return 0;
            }
        }
    vtysh_command_state_to(VTYSH_WAIT_INPUT); 
    return 0;
}

SInt32 vtysh_proc_exec_resp(T_VTYSH_CONN_CTX *ctx, UInt32 offset)
{
	T_VTYSH_MSG_HDR *RecvHead = NULL;
	char *data_ptr;
	int ret = 0;
	UInt32 data_len= 0;

	RecvHead = (T_VTYSH_MSG_HDR *)ctx->recBuf;
	CHECKNEEDSHOW(RecvHead);

	data_len=(ctx->recBufLen)-sizeof(T_VTYSH_MSG_HDR);
	data_ptr = (char *)RecvHead + sizeof(T_VTYSH_MSG_HDR);
	if(data_len > 0)
	{
    	/* 解决多包显示多一行问题 */
    	if(data_ptr[data_len - 1] == '\n')
    	{
    		data_ptr[data_len - 1] = '\0';
    	}

        printf("%s\n", data_ptr);
    }
    if(RecvHead->t_LastData.lastFlag == TRUE)
    {
        /* 翻转状态并结束 */               
	    vtysh_command_state_to(VTYSH_WAIT_INPUT);  
    }
    else
    {
        /* 等待用户输入空格，再发下个请求包 */
        ret = waitToSendNextReq();
        changeMode(1); 
        if(ret == 1)
        {
            send_req_server(ctx, RecvHead, 1);/* 当前只支持一个参数 */
        }
    }

    
	return 0;
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
	if((msgLen + offset > sizeof(ctx->recBuf)) || (ctx->recBufLen < offset))
	{
	    vtysh_command_state_to(VTYSH_WAIT_INPUT);
        printf("recv msg len out of range, msgLen = %d.\n", msgLen);
        return -1;
	}
	msgId = ntohl(msg_hdr->msgID);
	switch(msgId)
	{
	case VTYSH_EXEC_FAIL_RESP:
		ret = vtysh_proc_exec_resp_fail(ctx, offset);
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
		
	case VTYSH_EXEC_SUCC_RESP:
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
    tv.tv_sec = m_conn_ctx.stGlobalConf.ClientTimeOut;
    tv.tv_usec = 0;
    if (setsockopt(ictx->cli_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        printf("socket option  SO_RCVTIMEO not support\n");
        return NULL;
    }

	while(1)
	{
		vtysh_command_wait_state(VTYSH_WAIT_RESP);//不能加，如果加了，后面只要有一个回复延迟，就会导致后续命令seqno都对不上，进而导致都没法显示需要信息
        memset(ictx->recBuf, 0, sizeof(ictx->recBuf));
        memset(ictx->sndBuf, 0, sizeof(ictx->sndBuf));
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

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(ctx->stGlobalConf.port + cellIndex_g);
    server_addr.sin_addr.s_addr = inet_addr(ctx->stGlobalConf.ip);

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
	
	if((strlen(str) != 1) || (*str < '0') || (*str > '2'))
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
	m_conn_ctx.sndBufLen = 0;
	m_conn_ctx.recBufLen = 0;
    m_conn_ctx.seqNo = 0;

	pthread_mutex_init(&(m_conn_ctx.state_mutex), NULL);
 	pthread_mutex_unlock(&(m_conn_ctx.state_mutex));
	pthread_create(&(m_conn_ctx.recv_thread), NULL, vtysh_comm_recv_loop, &m_conn_ctx);

	return 0;
}

/*
SInt32 vtysh_command_destroy()
{
	void *result;
	m_conn_ctx.recv_running = 0;
	pthread_join(m_conn_ctx.recv_thread, &result);
	return 0;
}*/


