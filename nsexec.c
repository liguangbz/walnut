/*
 * nsexec.c
 * Based on nsexec.c which is Copyright (C) 2008,2009 IBM Corp.
 *
 * routines for cloning a walnut in a new set of namespaces
 *
 * Copyright (C) 2010-2013 Columbia University
 * Authors: Christoffer Dall <cdall@cs.columbia.edu>
 *          Jeremy C. Andrus <jeremya@cs.columbia.edu>
 *          Alexander Van't Hof <alexvh@cs.columbia.edu>
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
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/sched.h>

#define LOG_TAG "walnuts/nsexec"
#include <cutils/log.h>
#include <cutils/memory.h>
#include <cutils/misc.h>

#include "walnutd.h"
#include "walnut_console.h"
#include "util.h"

#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif

/* Linux clone flags not available in bionic's kernel headers */
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS            0x04000000      /* New utsname group? */
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC            0x08000000      /* New ipcs */
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER           0x10000000      /* New user namespace */
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID            0x20000000      /* New pid namespace */
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET            0x40000000      /* New network namespace */
#endif
#ifndef CLONE_IO
#define CLONE_IO                0x80000000      /* Clone io context */
#endif


int g_cgroup_pipe[2];

extern int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, ...);

int load_cgroup_dir(char *dest, int len)
{
	FILE *f = fopen("/proc/mounts", "r");
	char buf[200];
	char *name, *path, *fsname, *options, *p1, *p2, *s;
	if (!f)
		return 0;
	while (fgets(buf, sizeof(buf), f)) {
		name = strtok_r(buf, " ", &p1);
		path = strtok_r(NULL, " ", &p1);
		fsname = strtok_r(NULL, " ", &p1);
		options = strtok_r(NULL, " ", &p1);
		if (strcmp(fsname, "cgroup") != 0)
			continue;
		strncpy(dest, path, len);
		fclose(f);
		return 1;
	}
	fclose(f);
	return 0;
}

char *get_cgroup_folder(char *walnutname)
{
	char cgroupbase[100];
	char *folder;
	int ret;

	if (!load_cgroup_dir(cgroupbase, sizeof(cgroupbase)))
		return NULL;

	folder = malloc(MAX_PATH_LEN);
	if (!folder)
		return NULL;

	ret = snprintf(folder, MAX_PATH_LEN, "%s/%s", cgroupbase, walnutname);
	if (ret >= MAX_PATH_LEN) {
		free(folder);
		return NULL;
	}
	return folder;
}

char *create_cgroup(char *walnutname)
{
	int ret;
	char *cgroupname;

	cgroupname = get_cgroup_folder(walnutname);
	if (!cgroupname)
		return NULL;

	ret = mkdir(cgroupname, 0755);
	if (ret && errno != EEXIST)
		return NULL;
	return cgroupname;
}

int move_to_new_cgroup(struct walnut_args *args)
{
	char tasksfname[200];
	FILE *fout;
	char *cgroupname;
	int ret;

	ret = -1;

	cgroupname = create_cgroup(args->walnutname);
	if (!cgroupname)
		goto out;

	snprintf(tasksfname, sizeof(tasksfname), "%s/tasks", cgroupname);
	fout = fopen(tasksfname, "w");
	if (!fout)
		goto out;
	fprintf(fout, "%d\n", args->init_pid);
	fclose(fout);

	ALOGI("Moved %s (%d) into new cgroup (%s)",
	     args->walnutname, args->init_pid, cgroupname);
	ret = 0;
out:
	free(cgroupname);
	return ret;
}

int do_newcgroup(struct walnut_args *args)
{
	if (!args->start_args.newcgrp)
		return 0;

	return move_to_new_cgroup(args);
}

static int do_child(void *vargv)
{
	struct walnut_args *walnut_args = (struct walnut_args *)vargv;
	struct walnut_start_args *start_args = &walnut_args->start_args;
	char **argv;
	char *rootdir;
	char *walnutname;
	char *syserr;
	int ret;
	char buf[20];
	sigset_t sigset;

	argv = walnut_args->argv;
	walnutname = walnut_args->walnutname;
	rootdir = walnut_args->rootdir;


	ALOGD("Starting walnut:");
	ALOGD("==============");
	ALOGD("start_args");
	ALOGD("----------");
	ALOGD("noopt: %d", start_args->noopt);
	ALOGD("uts_ns: %d", start_args->uts_ns);
	ALOGD("ipc_ns: %d", start_args->ipc_ns);
	ALOGD("user_ns: %d", start_args->user_ns);
	ALOGD("net_ns: %d", start_args->net_ns);
	ALOGD("pid_ns: %d", start_args->pid_ns);
	ALOGD("mount_ns: %d", start_args->mount_ns);
	ALOGD("mnt_rootfs: %d", start_args->mnt_rootfs);
	ALOGD("mnt_tmpfs: %d", start_args->mnt_tmpfs);
	ALOGD("newpts: %d", start_args->newpts);
	ALOGD("newcgrp: %d", start_args->newcgrp);
	ALOGD("share_dalvik_cache: %d", start_args->share_dalvik_cache);
	ALOGD("sdcard_branch: %d", start_args->sdcard_branch);
	ALOGD("open_console: %d", start_args->open_console);
	ALOGD("autoswitch: %d", start_args->autoswitch);
	ALOGD("pid_file: %s", start_args->pid_file);
	ALOGD("wait: %d", start_args->wait);
	ALOGD("\nwalnut_args");
	ALOGD("---------");
	ALOGD("walnutname: %s", walnut_args->walnutname);
	ALOGD("rootdir: %s", walnut_args->rootdir);
	ALOGD("init_pid: %d", walnut_args->init_pid);
	ALOGD("restart_pid: %d", walnut_args->restart_pid);
	ALOGD("argc: %d", walnut_args->argc);
	ALOGD("walnut_socket: %d", walnut_args->walnut_socket);

	/* reset out umask and sigmask for init */
	umask(0000);
	sigemptyset(&sigset);
	sigprocmask(SIG_SETMASK, &sigset, NULL);

	/* Make sure init doesn't kill walnutD on bad walnut errors */
	ret = setpgid(0, 0);
	if (ret < 0)
		ALOGE("error setting pgid: %s", strerror(errno));

	/* Close walnut utility socket */
	close(walnut_args->walnut_socket);

	ALOGI("%s: do_child, mnt_rootfs:%d, rootdir=%s",
	      walnutname, start_args->mnt_rootfs, rootdir);

	/* chroot... */
	if (chroot(rootdir)) {
		syserr = "chroot";
		goto out_err;
	}
	if (chdir("/")) {
		syserr = "chdir /";
		goto out_err;
	}

	ALOGD("%s: waiting for cgroup entry...", walnutname);
	close(g_cgroup_pipe[1]);
	ret = read(g_cgroup_pipe[0], buf, sizeof(buf));
	close(g_cgroup_pipe[0]);
	if (ret == -1 || atoi(buf) < 1) {
		syserr = "cgroup entry";
		goto out_err;
	}

	/* check if we should remount devpts */
	if (start_args->newpts) {
		struct stat ptystat, ptsstat;
		argv++;
		ALOGD("%s: mounting /dev/pts", walnutname);
		if (lstat("/dev/ptmx", &ptystat) < 0) {
			if (symlink("/dev/pts/ptmx", "/dev/ptmx") < 0) {
				syserr = "symlink /dev/pts/ptmx /dev/ptmx";
				goto out_err;
			}
			chmod("/dev/ptmx", 0666);
		} else if ((ptystat.st_mode & S_IFMT) != S_IFLNK) {
			syserr = "Error: /dev/ptmx must be a link to "
				 "/dev/pts/ptmx\n"
				 "do:\tchmod 666 /dev/pts/ptmx\n   "
				 "\trm /dev/ptmx\n   "
				 "\tln -s /dev/pts/ptmx /dev/ptmx\n";
			goto out_err;
		}

		/* create /dev/pts directory if doesn't exist */
		if (stat("/dev/pts", &ptsstat) < 0) {
			if (mkdir("/dev/pts", 0666) < 0) {
				syserr = "mkdir /dev/pts";
				goto out_err;
			}
		} else {
			/* if container had no /dev/pts mounted don't fret */
			umount2("/dev/pts", MNT_DETACH);
		}

		if (mount("pts", "/dev/pts", "devpts", 0, "ptmxmode=666,newinstance") < 0) {
			syserr = "mount -t devpts -o newinstance";
			goto out_err;
		}
	}

	close(walnut_args->child_pipe[0]);
	buf[0] = 1;
	write(walnut_args->child_pipe[1], buf, 1);
	close(walnut_args->child_pipe[1]);

	ALOGD("%s: waiting for walnutD...", walnutname);
	close(walnut_args->init_pipe[1]);
	ret = read(walnut_args->init_pipe[0], buf, sizeof(buf));
	close(walnut_args->init_pipe[0]);
	if (ret == -1 || atoi(buf) < 1) {
		syserr = "walnutD communication";
		goto out_err;
	}
	ALOGD("%s: Starting init!", walnutname);

	/* touch a file in / to indicate to /init that we're in a walnut */
	creat("/.walnut", 0400);

	execve(walnut_args->argv[0], walnut_args->argv, NULL);
	syserr = "execve";

out_err:
	{
		int e = errno;
		ALOGE("ERROR{%s: errno=%d (%s)}", syserr, e, strerror(e));
	}
	return -1;
}

static int write_pid(char *pid_file, int pid)
{
	FILE *fp;

	if (!pid_file)
		return 0;

	fp = fopen(pid_file, "w");
	if (!fp)
		return -1;
	fprintf(fp, "%d", pid);
	fflush(fp);
	fclose(fp);
	return 0;
}

int do_share_dalvik_cache(char *root_path)
{
	char target[PATH_MAX];
	int ret = -1;

	ALOGI("Dalvik Cache: relocating %s/data/dalvik-cache...", root_path);

	snprintf(target, sizeof(target), "%s/data/dalvik-cache", root_path);
	mkdir(target, 0755);

	/* bind-mount the host's dalvik-cache directory into the walnut */
	ret = mount("/data/dalvik-cache", target, "none", MS_BIND, 0);
	if (ret < 0)
		ALOGW("Couldn't share Dalvik cache");

	return (ret < 0) ? -1 : 0;
}

int mount_dev_tmpfs(char *root_path)
{
	char target[PATH_MAX];
	struct stat st;
	int ret = -1;
	
	snprintf(target, sizeof(target), "%s/dev", root_path);
	if (stat(target, &st) < 0) {
		/* try to create the directory */
		if (mkdir(target, 0755) < 0) {
			ALOGE("cannot create <root>/dev: %s", strerror(errno));
			return -1;
		}
	}

	ret = mount("tmpfs", target, "tmpfs", 0, "mode=0755");
	if (ret < 0) {
		ALOGE("unable to mount tmpfs: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int do_clone(struct walnut_args *walnut_args)
{
	struct walnut_start_args *args = &walnut_args->start_args;
	int pid;
	size_t stacksize = 4 * sysconf(_SC_PAGESIZE);
	void *childstack, *stack = malloc(stacksize);
	unsigned long flags;
	char buf[20];

	if (!stack) {
		ALOGE("cannot allocate stack: %s", strerror(errno));
		return -1;
	}

	childstack = (char *)stack + stacksize;

	flags = SIGCHLD;
	if (args->uts_ns)
		flags |= CLONE_NEWUTS;
	if (args->ipc_ns)
		flags |= CLONE_NEWIPC;
	if (args->user_ns)
		flags |= CLONE_NEWUSER;
	if (args->net_ns)
		flags |= CLONE_NEWNET;
	if (args->pid_ns)
		flags |= CLONE_NEWPID;
	if (args->mount_ns)
		flags |= CLONE_NEWNS;

	pid = clone(do_child, childstack, flags, walnut_args);

	free(stack);
	if (pid < 0) {
		ALOGE("clone: %s", strerror(errno));
		return -1;
	}
	if (gettimeofday(&walnut_args->start_time, NULL) == -1)
		ALOGE("%s: gettimeofday failed: %s", __func__, strerror(errno));

	/*
	 * Put the new process in a cgroup if requested.
	 * Note that the child will block until we release it with a write
	 * into the global pipe. This ensures that all children of the walnut's
	 * init process will inherit the cgroup (i.e. a child will _not_ be
	 * forked before we can put init into a cgroup)
	 */
	walnut_args->init_pid = pid;
	do_newcgroup(walnut_args);

	snprintf(buf, sizeof(buf), "%d", pid);
	close(g_cgroup_pipe[0]);
	write(g_cgroup_pipe[1], buf, strlen(buf)+1);
	close(g_cgroup_pipe[1]);

	return pid;
}

/* Careful: When this is called, it's called from a different process.
 * That means, no signaling to walnutd's threads */
void tear_down_walnut(struct walnut_args *walnut_args, struct pty_info *console_pty)
{
	struct walnut_start_args *args = &walnut_args->start_args;
	cleanup_walnut_console(console_pty);

	/*
	if (args->RIL_PROXY) {
		CLEANUP RIL PROXY SOCKET
	}
	 */

	if (unmount_all(walnut_args->rootdir, args->mnt_rootfs) == -1)
		ALOGW("Couldn't unmount_all() on %s", walnut_args->rootdir);
}

static void thread_exit_handler(int sig)
{
	pthread_exit(0);
}

/* sd is used for sending more detailed error messages to client.
 * console_pty is filled in after returning. pty_info.ptm will be -1 if no
 * console is requested. */
int walnut_nsexec(int sd, struct walnut_args *walnut_args,
		char *name, struct pty_info *console_pty)
{
	struct walnut_start_args *args = &walnut_args->start_args;
	int pid = -1;
	char *rootdir = walnut_args->rootdir;
	struct sigaction actions;
	int ret;

	/* Setup signal handler for SIGUSR2 (fake pthread_cancel) */
	memset(&actions, 0, sizeof(actions));
	sigemptyset(&actions.sa_mask);
	actions.sa_flags = 0;
	actions.sa_handler = thread_exit_handler;
	if (sigaction(SIGUSR2, &actions, NULL) < 0)
		ALOGE("sigaction(%s): %s", name, strerror(errno));

	/* pipe to synchronize child execution and entry into new cgroup */
	if (pipe(g_cgroup_pipe)) {
		ALOGE("pipe: %s", strerror(errno));
		send_msg(sd, "1 nsexec failed: pipe() failed");
		goto err_cleanup;
	}

	/* pipes to synchronize child start and walnutD monitoring */
	if (pipe(walnut_args->child_pipe) || pipe(walnut_args->init_pipe)) {
		ALOGE("Can't create child/init pipes for '%s': %s",
		      name, strerror(errno));
		send_msg(sd, "1 nsexec failed: child/init pipe creating failed");
		goto err_cleanup;
	}

	if (args->mnt_rootfs) {
		if (mount_walnut(name, args->sdcard_branch)) {
			ALOGE("couldn't mount '%s' rootfs: %d", name, errno);
			send_msg(sd, "1 nsexec failed: mount() rootfs failed");
			goto err_cleanup;
		}
	}

	if (args->mnt_tmpfs) {
		if (mount_dev_tmpfs(rootdir) < 0) {
			ALOGE("couldn't mount '%s' tmpfs: %d", name, errno);
			send_msg(sd, "1 nsexec failed: mount() tmpfs failed");
			goto err_cleanup;
		}
	}

	if (args->share_dalvik_cache)
		do_share_dalvik_cache(rootdir);

	if (args->open_console) {
		ALOGD("Opening console for '%s'", name);
		int ret = create_walnut_console(rootdir, console_pty);
		if (ret < 0) {
			ALOGE("Couldn't open console in '%s'. "
			      "Continuing nsexec..", name);
			console_pty->ptm = -1;
		}
	} else
		console_pty->ptm = -1;

	walnut_args->walnut_socket = sd;
	ALOGI("Cloning '%s'", name);
	pid = do_clone(walnut_args);

	if (pid == -1) {
		ALOGE("clone(%s) failed: tearing down walnut", name);
		goto err_cleanup;
	}

	write_pid(args->pid_file, pid);

	close(walnut_args->child_pipe[1]);
	close(walnut_args->init_pipe[0]);

	ALOGI("Successfully initialized '%s' with init PID %d", name, pid);
	return pid;

err_cleanup:
	tear_down_walnut(walnut_args, console_pty);
	return -1;
}
