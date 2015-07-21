/*
 * walnutd.h
 *
 * Structures and definitions for the walnuts controlling daemon, walnutd
 *
 * Copyright (C) 2010-2013 Columbia University
 * Authors: Christoffer Dall <cdall@cs.columbia.edu>
 *          Jeremy C. Andrus <jeremya@cs.columbia.edu>
 *          Alexander Van't Hof <alexvh@cs.columbia.edu>
 *          Li Guang <guang.li@godinsec.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */
#ifndef WALNUTD_H
#define WALNUTD_H

#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>

#include <linux/sched.h>
#include <linux/socket.h>

#include "walnut_console.h"

#define SOCKET_PATH "/data/walnutd"
#define PRIV_SOCKET_PATH "TODO"
#define WALNUTD_LOCKFILE "/data/.walnutdlock"
#define WALNUT_ETC_PATH "/system/etc/walnut"
#define DEFL_WALNUT_DIR "/data/walnuts"
#define DEFL_SDCARD_ROOT "/mnt/shell/emulated/walnuts"
#define DEFL_START_OPTS "-CMSdgimptu"
#define CONSOLE_READY_MSG "ready"
#define CONSOLE_READY_MSG_LEN 8 /* strlen("0 ready") + sizeof('\0') */
#define MAX_MSG_LEN 512
#define MAX_NAME_LEN 64
#define MAX_ARGS 20
#define MAX_PATH_LEN 256

/* Update WALNUT_CMD_REV if you change this enum in any way */
enum walnut_cmd {
	WALNUT_CREATE,
	WALNUT_DESTROY,
	WALNUT_LIST,
	WALNUT_NEXT,
	WALNUT_PREV,

	WALNUT_START,
	WALNUT_STOP,
	WALNUT_SWITCH,
	WALNUT_CONSOLE,

	WALNUT_AUTOSTART,
	WALNUT_AUTOSWITCH,
	WALNUT_GETID,
	WALNUT_SETID,
	WALNUT_GETACTIVE,
	WALNUT_MOUNT,
	WALNUT_UNMOUNT,

	WALNUT_RUNCMD,

	WALNUT_MAXCOMMAND
};

/* Update WALNUT_CMD_REV if you change this struct in any way */
struct walnut_create_args {
	int id; /* -1: unspecified */
};

/* Update WALNUT_CMD_REV if you change this struct in any way */
struct walnut_list_args {
	char all;
	char running;
	char zombie;
};

/* Update WALNUT_CMD_REV if you change this struct in any way */
struct walnut_start_args {
	char noopt; /* no start opions - use default or stored */
	char uts_ns;
	char ipc_ns;
	char user_ns;
	char net_ns;
	char pid_ns;
	char mount_ns;
	char mnt_rootfs;
	char mnt_tmpfs;
	char newpts;
	char newcgrp;
	char share_dalvik_cache;
	char sdcard_branch;
	char open_console;
	char autoswitch;
	char pid_file[MAX_PATH_LEN];
	char wait;
};

/* Update WALNUT_CMD_REV if you change this struct in any way */
/* if neither field is set, the status is retrieved */
struct walnut_autostart_args {
	char on;
	char off;
};

/* Update WALNUT_CMD_REV if you change this struct in any way */
struct walnut_setid_args {
	int id;
};

/* Update WALNUT_CMD_REV if you change this struct in any way */
struct walnut_mount_args {
	int all;
};

/* Update WALNUT_CMD_REV if you change this struct in any way */
struct walnut_runcmd_args {
	char cmd[MAX_PATH_LEN];
};

/* Update this number if you change walnut_cmd_arg in any way */
#define WALNUT_CMD_REV (0xbabe0010)
struct walnut_cmd_arg {
	enum walnut_cmd cmd;
	char walnutname[MAX_NAME_LEN];
	union {
		struct walnut_create_args		create_args;
		struct walnut_list_args		list_args;
		struct walnut_start_args		start_args;
		struct walnut_setid_args		setid_args;
		struct walnut_mount_args		mount_args;
		struct walnut_autostart_args	autostart_args;
		struct walnut_runcmd_args		runcmd_args;
	};
};

struct walnut_args {
	struct walnut_start_args start_args;
	char walnutname[MAX_NAME_LEN];
	struct timeval start_time;
	char *rootdir;
	int init_pid;
	int restart_pid;
	char **argv;
	int argc;
	int walnut_socket;
	int child_pipe[2];
	int init_pipe[2];
};

struct walnut_node {
	short init_pid;
	char name[MAX_NAME_LEN];
	struct pty_info console_pty;
	short starting;
	short id;
	short non_child;
	struct timeval start_time;
	struct walnut_node *next;
	struct walnut_node *prev;
};

struct walnut_list {
	struct walnut_node *head;
	struct walnut_node *tail;
	pthread_mutex_t mutex;
};

struct walnut_monitor_state {
	char name[MAX_NAME_LEN];
	int pid;
	int child_fd;
	int init_fd;
};

extern struct walnut_node *active_walnut;
struct walnut_node *search_walnuts_path(char *root_path);
void switch_to_next(void);

int init_addr(struct sockaddr_un *addr);
int _send_msg(int fd, const char *fmt, va_list ap);
int send_msg(int fd, const char *fmt, ...);
int recv_msg_len(int fd, char **tok, char **msg, int len);
int recv_msg(int fd, char **tok, char **msg);
int send_fd(int conn_fd, int fd);
int recv_fd(int conn_fd);

extern char *get_rw_path(char *name);
extern char *get_root_path(char *name);
extern int do_share_dalvik_cache(char *root_path);

int mount_walnut(char *name, int sdcard_mnt);
int unmount_all(const char *root_path, int mount_fs);

/* non-exported bionic functions */
extern pid_t __pthread_gettid(pthread_t tid);

#endif /* WALNUTD_H */
