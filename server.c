#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>

typedef unsigned int    UInt32;
typedef unsigned short  UInt16;
typedef unsigned char   UInt8;
typedef int    			SInt32;
typedef short  			SInt16;
typedef char   			SInt8;
typedef unsigned long long UInt64;

#define VTYSH_INIT_REQ        (0x20200001)
#define VTYSH_INIT_FAIL_RESP  (0x20200002)
#define VTYSH_INIT_SUCC_RESP  (0x20200003)

#define VTYSH_EXEC_REQ        (0x20200004)
#define VTYSH_EXEC_RESP       (0x20200005)
#define VTYSH_DISCONN_REQ     (0x20200006)

#define SIZEOF_UINT8        1
#define SIZEOF_UINT16       2
#define SIZEOF_UINT32       4
#define SIZEOF_UINT64       8

#define VTYSH_BUFFER_SZ       4000

//extern UInt8 mac_cellIndex_g;

int sockfd = -1;
 
typedef int(*VtyshCmd)(int argc, char **argv);

typedef struct{ 
    UInt16 srcPort;
    UInt16 dstPort;
    UInt32 seqNo;
    char   srcIp[20];
    char   dstIp[20];
    char   sendBuf[VTYSH_BUFFER_SZ];
    struct sockaddr_in cli_adrr;
}T_VTYSH_CTX;


typedef struct {
    char *pCmdString;
    UInt32   Argc;
    VtyshCmd Func;
    char *pcCommandHelp;
}T_VTYSH_COMMAND;


typedef struct{
    UInt32 msgID;
    UInt32 msgLen;
    UInt32 seqNo;
}T_VTYSH_MSG_HDR;


typedef struct{
    UInt32 sessNo;
    char   srcIp[20];
    UInt16 srcPort;
    char   dstIp[20];
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
    UInt32 ArgcLen;
    char data[];
}T_VTYSH_EXEC_REQ_HDR;


typedef struct{
    UInt32 Idx;
    UInt32 DataLen;
    char data[];
}T_VTYSH_EXEC_RESP_HDR;

//extern T_CmacDataCenter *ptCMACDataCenter_g;
//extern tickType dlStatTempTick_g;

#define VTYSH_MAX_REQ_NUM         500

T_VTYSH_COMMAND *cmdVtyshAllReg_g[VTYSH_MAX_REQ_NUM] = {NULL};

T_VTYSH_CTX vtysh_ctx_g;

//extern int ulcmac_set_schedule_method(int argc, char *agrv);

int print_Dci0Lost_method(int argc,char *argv)
{
	char CliBuf[20];
	int tmp = 2468;
	//int cli_msglen = snprintf(CliBuf,20,"dci dtx cnt:%d",ptCMACDataCenter_g->cmacCellStat[mac_cellIndex_g].ueStat[ue_idx].wDciDtxCnt);
	int cli_msglen = snprintf(CliBuf,20,"dci0 lost:%d",tmp);
	sleep(10);
	lteVtyshExecResp(cli_msglen,CliBuf);
	return 0;
}
int print_DciDtxCnt_method(int argc,char *argv)
{
	char CliBuf[20];
	int tmp = 1234;
	//int cli_msglen = snprintf(CliBuf,20,"dci dtx cnt:%d",ptCMACDataCenter_g->cmacCellStat[mac_cellIndex_g].ueStat[ue_idx].wDciDtxCnt);
	int cli_msglen = snprintf(CliBuf,20,"dci dtx cnt:%d",tmp);
	lteVtyshExecResp(cli_msglen,CliBuf);
	return 0;
}

const T_VTYSH_COMMAND dlcmacVtyshCli_g[] =
{			

};	


const T_VTYSH_COMMAND ulcmacVtyshCli_g[] = 
{
	{"pdcch dci0lost",0,  print_Dci0Lost_method,"pdcch info\r dci0 lost count"},
	{"pdcch dcidtxcnt",0, print_DciDtxCnt_method,"pdcch info\r dci lost count"}

};

SInt32 lteVtyshSendRawData(char *data, UInt32 dataLen)
{
	sendto(sockfd,data,dataLen,0,(struct sockaddr*)&vtysh_ctx_g.cli_adrr,sizeof(vtysh_ctx_g.cli_adrr));

}


SInt32 lteVtyshSendCmdDescPart(SInt32 *start_idx)
{
    memset(vtysh_ctx_g.sendBuf, 0, sizeof(vtysh_ctx_g.sendBuf));
    T_VTYSH_MSG_HDR *msg_hdr = (T_VTYSH_MSG_HDR *)(vtysh_ctx_g.sendBuf);
    SInt32 reg_idx = 0;
    T_VTYSH_COMMAND *cmd;
    SInt32 help_len;
    SInt32 cmd_len;
    SInt32 finished = 0;

    UInt32 left_len = VTYSH_BUFFER_SZ - sizeof(T_VTYSH_MSG_HDR);
    UInt32 offset = sizeof(T_VTYSH_MSG_HDR);
    T_VTYSH_CMD_DESC_HDR *cmd_desc = NULL;

    reg_idx = *start_idx;// 
    
    while(1)
    {
        if(reg_idx >= VTYSH_MAX_REQ_NUM || cmdVtyshAllReg_g[reg_idx] == NULL)
        {
            finished = 1;
            break;
        }
        cmd = cmdVtyshAllReg_g[reg_idx];
        cmd_len = strlen(cmd->pCmdString) + 1;
        help_len = strlen(cmd->pcCommandHelp) + 1;
        
        if(cmd_len + help_len + sizeof(T_VTYSH_CMD_DESC_HDR) > left_len)
        {
            break;
        }
        else
        {
           cmd_desc = (T_VTYSH_CMD_DESC_HDR *)(vtysh_ctx_g.sendBuf + offset);
           cmd_desc->Idx = htonl(reg_idx);
           cmd_desc->Argc = htonl(cmd->Argc);
           cmd_desc->cmdLineLen = htons(cmd_len);
           cmd_desc->cmdHelpLen = htons(help_len);
           
           memcpy(cmd_desc->data, cmd->pCmdString, cmd_len);
           memcpy(cmd_desc->data+cmd_len, cmd->pcCommandHelp, help_len);
           offset += cmd_len + help_len + sizeof(T_VTYSH_CMD_DESC_HDR);
           left_len -= cmd_len + help_len + sizeof(T_VTYSH_CMD_DESC_HDR);
        }
        reg_idx++;
    }

    if(offset > sizeof(T_VTYSH_MSG_HDR))
    {
        msg_hdr->msgLen = htonl(offset);
        msg_hdr->msgID  = htonl(VTYSH_INIT_SUCC_RESP);
        lteVtyshSendRawData(vtysh_ctx_g.sendBuf,offset);
    }

    if(finished)
    {
        return 0;
    }
    else
    {
        *start_idx = reg_idx;
        return 1;
    }
}


SInt32 lteVtyshExecResp(UInt32 msgLen, char *msg)
{
    T_VTYSH_MSG_HDR *msg_hdr = (T_VTYSH_MSG_HDR *)(vtysh_ctx_g.sendBuf);

    msg_hdr->msgID = htonl(VTYSH_EXEC_RESP);
    msg_hdr->seqNo = vtysh_ctx_g.seqNo;
    char *data = (char *)msg_hdr + sizeof(T_VTYSH_MSG_HDR);
    
    if(msgLen+sizeof(T_VTYSH_MSG_HDR) > VTYSH_BUFFER_SZ)
    {
        memcpy(data , msg, VTYSH_BUFFER_SZ-sizeof(T_VTYSH_MSG_HDR));
        lteVtyshSendRawData(vtysh_ctx_g.sendBuf, VTYSH_BUFFER_SZ);
    }
    else
    {
        memcpy(data, msg, msgLen);
        lteVtyshSendRawData(vtysh_ctx_g.sendBuf, msgLen+sizeof(T_VTYSH_MSG_HDR));
    } 
    return 0;
}


UInt8 lteVtyshInitCtx()
{
    int32_t reg_idx = 0;
    int32_t i=0;
    
    memset(&vtysh_ctx_g, 0, sizeof(T_VTYSH_CTX));

    for(i=0; i< sizeof(dlcmacVtyshCli_g)/sizeof(T_VTYSH_COMMAND);i++)
    {
        if(reg_idx < VTYSH_MAX_REQ_NUM)
            cmdVtyshAllReg_g[reg_idx++] = &(dlcmacVtyshCli_g[i]);
    }
    for(i=0; i< sizeof(ulcmacVtyshCli_g)/sizeof(T_VTYSH_COMMAND);i++)
    {
        if(reg_idx < VTYSH_MAX_REQ_NUM)
            cmdVtyshAllReg_g[reg_idx++] = &(ulcmacVtyshCli_g[i]);
    }
    return 0;
}


SInt32 lteVtyshParseInitReq(UInt32 dataLen, char *data)
{

    SInt32 reg_idx = 0;
    SInt32 ret;


 
 

    ret = lteVtyshSendCmdDescPart(&reg_idx);
    while(ret)
    {
        ret = lteVtyshSendCmdDescPart(&reg_idx);
    }
    return 1;
}

SInt32 lteVtyshParseExecReq(UInt32 dataLen, char *data)
{
    T_VTYSH_EXEC_REQ_HDR *exec_req = (T_VTYSH_EXEC_REQ_HDR*)data;
    UInt32 idx = ntohl(exec_req->Idx);
    UInt32 arg_len = ntohl(exec_req->ArgcLen);
    T_VTYSH_COMMAND *vtysh_cmd = NULL;
    char *argv_data = NULL;
    SInt32 ret;	
	int argc = 0;
	char *argv[20];

    if(idx>=VTYSH_MAX_REQ_NUM || cmdVtyshAllReg_g[idx]==NULL)
    {      
        // 
        return -1;
    }
	
    vtysh_cmd = cmdVtyshAllReg_g[idx];
    ret = vtysh_cmd->Func(argc, argv); 

    return ret;
}


SInt32 lteVtyshParseDisconnReq(UInt32 dataLen, char *data)
{
    T_VTYSH_INIT_REQ *init_req = (T_VTYSH_INIT_REQ*)data;
    UInt16 dstPt = init_req->dstPort;
    UInt16 srcPt = init_req->srcPort;
    UInt32 sessNo = init_req->sessNo; 

    if(dstPt ==  vtysh_ctx_g.dstPort && srcPt ==  vtysh_ctx_g.srcPort
       && !memcmp(init_req->srcIp, vtysh_ctx_g.srcIp, 20) 
       && !memcmp(init_req->dstIp, vtysh_ctx_g.dstIp, 20))
    {
        memset(vtysh_ctx_g.srcIp, 0, 20);
        memset(vtysh_ctx_g.dstIp, 0, 20);
        //vtysh_ctx_g.connLastTick = 0;
    }
       
    return 0;
}
/*
SInt32 lteVtyshCheckSessionNO(UInt32 sessNo)
{
    if(vtysh_ctx_g.connState && vtysh_ctx_g.connSess == sessNo)
        return 1;
    return 0;
}*/

UInt8  lteVtyshParseMsg(UInt8 *vtyshMsg, int len)
{
    UInt32 msgID = 0;
    UInt32 msgLen = 0;
    T_VTYSH_MSG_HDR *msg_hdr = NULL;

    msg_hdr = (T_VTYSH_MSG_HDR *)vtyshMsg;
    msgID = ntohl(msg_hdr->msgID);
    msgLen = ntohl(msg_hdr->msgLen);
    vtysh_ctx_g.seqNo = msg_hdr->seqNo;
	char *data = (char *)msg_hdr + sizeof(T_VTYSH_MSG_HDR);
    switch(msgID)
    {
        case VTYSH_INIT_REQ:
            lteVtyshParseInitReq(msgLen, data);
            break;
        case VTYSH_EXEC_REQ:
            lteVtyshParseExecReq(msgLen, data);
            break;
        case VTYSH_DISCONN_REQ:
          
                lteVtyshParseDisconnReq(msgLen, data);
           
            break;           
        default:
            lteVtyshParseInitReq(msgLen, data);
            break;
    }
    return 0;
}

int main(int arg, char **argv){
	struct sockaddr_in cli_addr;
	struct sockaddr_in ser_adrr;
	int addr_len;
	//int sockfd1 = -1;
	char ipBuf[20] = {0};
	
	lteVtyshInitCtx();
	
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (sockfd < 0) {
        printf("socket error");
        return -1;
    }

    ser_adrr.sin_family  = AF_INET;
    ser_adrr.sin_port = htons(60000 + atoi(argv[1]));
    ser_adrr.sin_addr.s_addr = inet_addr("10.109.9.31");//
    addr_len = sizeof(struct sockaddr_in);
	
    int ret = -1;
    ret = bind(sockfd, (struct sockaddr*)&ser_adrr, addr_len);
    if (ret < 0){
        printf("bind error\n");
        return -1;
    }

	char cli_msg[4096] = {0};
	while(1)
	{
		int len = recvfrom(sockfd, cli_msg, sizeof(cli_msg),0,(struct sockaddr*)&cli_addr, &addr_len);
       

		if(len > 0)
		{
              memcpy(&(vtysh_ctx_g.cli_adrr), &cli_addr, sizeof(cli_addr));
              inet_ntop(AF_INET, &cli_addr.sin_addr.s_addr, ipBuf, sizeof(ipBuf));
		      printf("ip: %s,  port %d  recev len: %d. \n", ipBuf, ntohs(cli_addr.sin_port), len);
		      lteVtyshParseMsg(cli_msg, len);
		}

		
	}		
    close(sockfd);
    return 0;
}

//sendto(sockfd, cli_msg, len, 0, (struct sockaddr*)&cli_addr, addr_len); 


