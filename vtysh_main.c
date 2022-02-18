/* Virtual terminal interface shell.
 * Copyright (C) 2000 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include "vtysh.h"
#include "command.h"
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <pthread.h>
#include "mcommands.h"

/* Initialization of signal handles. */
#include <readline/readline.h>
#include <readline/history.h>
#include "cJSON.h"




T_GlobalConfig g_GlobalInfo = {0};
extern T_VTYSH_CONN_CTX m_conn_ctx;
static void my_sig(int sig)
{
	// ctrl+ c后可以敲命令
        vtysh_command_state_to(VTYSH_WAIT_INPUT);

        rl_replace_line("", 0);
        rl_crlf();
        rl_forced_update_display();
        
}

SOCKET sock_g;
unsigned char cellIndex_g = 0;


static void signal_init ()
{
  signal (SIGINT, my_sig );
  signal (SIGTSTP, SIG_IGN);
  signal (SIGPIPE, SIG_IGN);

}


static void in_show_welcome()
{
	char build[1024];
	FILE *fp;

	sprintf(build, "Build On %s %s. Version 1.0.1", __DATE__, __TIME__);
	fp = fopen("/BUILD", "r");
	if(fp)
	{
		fgets(build, sizeof(build), fp);
		fclose(fp);
	}
	vty_out (vty, "%s\n", build);
}

void install_LteCommand()
{
    memset(&m_conn_ctx, 0, sizeof(m_conn_ctx));
    SOCKADDR_IN server_addr;
    unsigned int addr_len = 0;

    sock_g = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);  
    if(sock_g  < 0)
    {
        printf("cli socket create failed\n");
        return;
    }
	T_VTYSH_MSG_HDR *msg_hdr = NULL;
	int len = 0;

	msg_hdr = (T_VTYSH_MSG_HDR *)(m_conn_ctx.sndBuf);	
	msg_hdr->msgID = htonl(VTYSH_INIT_REQ);
	msg_hdr->period = g_GlobalInfo.ServerGetPeirod;
	msg_hdr->msgLen = htonl(0);

	m_conn_ctx.sndBufLen = sizeof(T_VTYSH_MSG_HDR);
	strncpy(m_conn_ctx.dstIp, g_GlobalInfo.ip, 20);
	m_conn_ctx.dstPort = g_GlobalInfo.port + 0;//只去小区0搜集命令消息
	m_conn_ctx.cli_sock = sock_g;

    printf("connecting...\n");
	while(len <= 0)
	{  
    	vtysh_command_send_packet(&m_conn_ctx);
    	len = recvfrom(sock_g, m_conn_ctx.recBuf, VTYSH_REC_BUFFER_SZ, 0, (struct sockaddr*)&server_addr, &addr_len);
        if(len > 0)
        {
            m_conn_ctx.recBufLen = len;
            vtysh_parse_comm_ind(&m_conn_ctx);
            printf("conneted!\n");
        }
    }
    

	return;
    

}

void global_init()
{
    strncpy(g_GlobalInfo.ip, "10.11.1.131", 20);
    g_GlobalInfo.port = 60000;
    g_GlobalInfo.ClientTimeOut = 10;
    g_GlobalInfo.ServerGetPeirod = 1;
}


void parse_global_config()
{
    FILE *f;
	int len = 0;
    char * jsonStr = NULL;
    cJSON * root = NULL;
	cJSON * object = NULL;
    cJSON * item = NULL;//cjson对象
	
	f = fopen("Config.txt","r");
	if(NULL == f)
	{
        return;
	}
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);
	
	jsonStr = (char *)malloc((len + 1)* sizeof(char));
	fread(jsonStr, 1, len, f);
	fclose(f);

    root = cJSON_Parse(jsonStr);     
    if (!root) 
    {
        printf("Parse JSON Error.\n");
    }
    else
    {
        object = cJSON_GetObjectItem(root, "ServerPara");
		item = cJSON_GetObjectItem(object, "ServerIpAddress");
		strncpy(g_GlobalInfo.ip,item->valuestring,sizeof(g_GlobalInfo.ip));
		item = cJSON_GetObjectItem(object, "ServerPort");
		g_GlobalInfo.port = item->valueint;
		item = cJSON_GetObjectItem(object, "ServerGetPeriod");
		g_GlobalInfo.ServerGetPeirod = item->valueint;
        

		object = cJSON_GetObjectItem(root, "ClientPara");
		item = cJSON_GetObjectItem(object, "RecvTimeOut");
		g_GlobalInfo.ClientTimeOut = item->valueint;
		cJSON_Delete(root);
    }
	
	free(jsonStr);
    return; 

}

/* VTY shell main routine. */

UInt32 main_is_running = 1;
int main (int argc, char **argv, char **env)
{
	char *line;
//	int opt;




	/* Init the cmd */
	cmd_init();

	/* Init the vtysh */
	vtysh_init_vty ();

	//TODO load the dynamic so

	/* sort the node */
	cmd_sort_node();

	in_show_welcome();

    global_init();
    
	parse_global_config();
	
	vtysh_command_ins_sys();

	install_LteCommand();

	vtysh_command_init();

		  	/* Signal and others. */
	signal_init ();
	
	vtysh_command_state_to(VTYSH_WAIT_INPUT);
	
	/* Main command loop. */
	while (main_is_running)
	{
		vtysh_command_wait_state(VTYSH_WAIT_INPUT);		
		line = vtysh_readline();
		if(line != NULL)
		{
			vtysh_execute(line);   
			//vtysh_command_state_to(VTYSH_WAIT_RESP);
        }
        
	}
	//vtysh_command_destroy();
	

	exit (0);
}
