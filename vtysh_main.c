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

static void my_sig(int sig)
{
	// ctrl+ c 
	rl_replace_line("", 0);
	rl_crlf();
	rl_forced_update_display();
}

#if 0
static void signal_init ()
{
  signal (SIGINT, my_sig );
  signal (SIGTSTP, SIG_IGN);
  signal (SIGPIPE, SIG_IGN);

}
#endif

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

/* VTY shell main routine. */

UInt32 main_is_running = 1;
int main (int argc, char **argv, char **env)
{
	char *line;
//	int opt;

  	/* Signal and others. */
//	signal_init ();

	/* Init the cmd */
	cmd_init();

	/* Init the vtysh */
	vtysh_init_vty ();

	//TODO load the dynamic so

	/* sort the node */
	cmd_sort_node();

	in_show_welcome();

	vtysh_command_init();
	
	vtysh_command_ins_sys();
	
	vtysh_command_state_to(VTYSH_WAIT_INPUT);
	
	/* Main command loop. */
	while (main_is_running)
	{
		vtysh_command_wait_state(VTYSH_WAIT_INPUT);		
		line = vtysh_readline();
		if(line != NULL)
			vtysh_execute(line);
	}
	//vtysh_command_destroy();
	
	printf ("\n");
	exit (0);
}
