/*
 * walnutd.c
 *
 * The Cells controlling daemon, walnutd
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
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/sched.h>
#include <linux/socket.h>

#define LOG_TAG "walnutd"
#include <cutils/log.h>
#include <cutils/memory.h>
#include <cutils/misc.h>
#include "array.h"

#include "walnutd.h"
#include "walnut_config.h"
#include "walnut_console.h"
#include "nsexec.h"
#include "util.h"

#define MAX_WALNUT_AUTOSTART_ATTEMPTS 5
#define TEMP_TOKEN "whoareyou"

char *g_walnut_dir = DEFL_WALNUT_DIR;
char *g_sdcard_root = DEFL_SDCARD_ROOT;

static struct walnut_list g_walnut_list = {
	.head = NULL,
	.tail = NULL,
	.mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER
};

static struct walnut_list g_dead_walnut_list = {
	.head = NULL,
	.tail = NULL,
	.mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER
};

static Array *autostarted_array;

struct walnut_node *active_walnut = NULL;
pthread_mutex_t active_walnut_lock = PTHREAD_MUTEX_INITIALIZER;

/* We have to prevent walnuts from being destroyed while starting or while
 * changing configuration options - basically a lock for the .walnutconf dir */
pthread_mutex_t config_lock = PTHREAD_MUTEX_INITIALIZER;

/* sigchld handler */
pthread_mutex_t sigchld_lock = PTHREAD_MUTEX_INITIALIZER;

static void walnut_cleanup_and_free(struct walnut_node *walnut, const char *root_path,
				  struct walnut_list *list);

/* Search through walnuts list by walnut name */
static struct walnut_node *__search_walnuts(char *name, struct walnut_list *list)
{
	struct walnut_node *walnut;

	pthread_mutex_lock(&list->mutex);
	walnut = list->head;
	while (walnut != NULL) {
		if (strcmp(walnut->name, name) == 0)
			break;
		walnut = walnut->next;
	}
	pthread_mutex_unlock(&list->mutex);
	return walnut;
}

static struct walnut_node *search_walnuts(char *name)
{
	return __search_walnuts(name, &g_walnut_list);
}

static struct walnut_node *search_dead_walnuts(char *name)
{
	return __search_walnuts(name, &g_dead_walnut_list);
}

/* Search through walnuts list based on the root path. */
struct walnut_node *search_walnuts_path(char *root_path)
{
	char name[MAX_NAME_LEN];
	if (basename_r(root_path, name, MAX_NAME_LEN) < 0) {
		ALOGE("Could not obtain basename from root_path");
		return NULL;
	}
	return search_walnuts(name);
}

static struct walnut_node *search_walnuts_pid(int pid, struct walnut_list *list)
{
	struct config_info config;
	struct walnut_node *walnut;

	pthread_mutex_lock(&list->mutex);
	walnut = list->head;
	while (walnut != NULL) {
		if (read_config(walnut->name, &config) == 0)
			if (config.initpid == pid ||
			    config.restart_pid == pid)
				break;
		walnut = walnut->next;
	}
	pthread_mutex_unlock(&list->mutex);

	return walnut;
}


static struct walnut_node *
__get_next_or_prev_walnut(struct walnut_node *cur, int next)
{
	struct walnut_node *walnut = NULL;
	/* Lock the list so no changes can be made to cur->next/prev */
	pthread_mutex_lock(&g_walnut_list.mutex);
	if (cur == NULL ||
	    (cur->next == NULL && cur->prev == NULL)) {
		goto err_get_next_or_prev_walnut;
	}
	if (next) {
		if (cur->next != NULL)
			walnut = cur->next;
		else
			walnut = g_walnut_list.head;
	} else {
		if (cur->prev != NULL)
			walnut = cur->prev;
		else
			walnut = g_walnut_list.tail;
	}
err_get_next_or_prev_walnut:
	pthread_mutex_unlock(&g_walnut_list.mutex);
	return walnut;
}

/* Returns the walnut started next after cur, loops back to head node
 * if necessary 0. NULL if cur is NULL or only 1 walnut is running */
static struct walnut_node *get_next_walnut(struct walnut_node *cur)
{
	return __get_next_or_prev_walnut(cur, 1);
}
static struct walnut_node *get_prev_walnut(struct walnut_node *cur)
{
	return __get_next_or_prev_walnut(cur, 0);
}

/* Create a new walnut_node */
static struct walnut_node *
create_walnut_node(char *name, struct config_info *config,
		 struct pty_info *console_pty)
{
	struct walnut_node *new = calloc(sizeof(*new), 1);
	if (new == NULL)
		return NULL;
	memset(new, 0, sizeof(*new));
	new->init_pid = config->initpid;
	new->starting = 1;
	new->id = config->id;
	int n = snprintf(new->name, MAX_NAME_LEN, "%s", name);
	if (n >= MAX_NAME_LEN || n < 0) {
		free(new);
		ALOGE("invalid walnut name (must be < %d chars): \"%s\"",
		     MAX_NAME_LEN, name);
		return NULL;
	}
	memcpy(&new->console_pty, console_pty, sizeof(*console_pty));
	return new;
}

static void __add_walnut_to(struct walnut_node *walnut, struct walnut_list *list)
{
	pthread_mutex_lock(&list->mutex);
	walnut->next = NULL;
	walnut->prev = NULL;
	if (list->head == NULL) { /* Empty list */
		list->head = walnut;
		list->tail = walnut;
	}
	else { /* Add to end of list */
		walnut->prev = list->tail;
		list->tail->next = walnut;
		list->tail = walnut;
	}
	pthread_mutex_unlock(&list->mutex);
}

static void __del_walnut_from(struct walnut_node *walnut, struct walnut_list *list)
{
	pthread_mutex_lock(&list->mutex);
	if (walnut->prev != NULL)
		walnut->prev->next = walnut->next;
	if (walnut->next != NULL)
		walnut->next->prev = walnut->prev;

	if (list->head == walnut)
		list->head = walnut->next;
	if (list->tail == walnut)
		list->tail = walnut->prev;
	pthread_mutex_unlock(&list->mutex);
}

/* Add a walnut_node to walnuts list */
static void add_walnut_node(struct walnut_node *new)
{
	__add_walnut_to(new, &g_walnut_list);
}

static void mark_walnut_deleted(struct walnut_node *walnut)
{
	/* remote the walnut from active list */
	__del_walnut_from(walnut, &g_walnut_list);

	/*
	 * add the node to the "deleted list"
	 * so SIGCHLD handler can find it
	 */
	__add_walnut_to(walnut, &g_dead_walnut_list);
}


/* Constructs a root_path from g_walnut_dir and given name.
 * Don't forget to free the result */
char *get_root_path(char *name)
{
	/* +2 for '\0' and '/' */
	char *root_path = malloc(strlen(g_walnut_dir) + strlen(name) + 2);
	if (root_path == NULL) {
		ALOGE("Failed to malloc for root_path: %s", strerror(errno));
		return NULL;
	}
	sprintf(root_path, "%s/%s", g_walnut_dir, name);
	return root_path;
}

/* Constructs the rw folder path from given root_path.
 * Don't forget to free the result. */
char *get_rw_path(char *name)
{
	/* +5 for "/-rw\0" */
	char *rw_path = malloc(strlen(g_walnut_dir) + strlen(name) + 5);
	if (rw_path == NULL) {
		ALOGE("Failed to malloc for rw_path: %s", strerror(errno));
		return NULL;
	}
	sprintf(rw_path, "%s/%s-rw", g_walnut_dir, name);
	return rw_path;
}

static const char *rootfs_excludes[] = {
	"init.usb.rc",
	"adbd",
	"storage",
	NULL
};

void copyfs_callback(void *ctx, const char *path, struct dirent *e)
{
	const char ** ex;
	struct stat st, walnut_st;
	int use_stat;
	char newpath[PATH_MAX];
	char linkpath[PATH_MAX];
	const char *root_path = (const char *)ctx;

	if (!e || !root_path)
		return;

	/* don't duplicate anything in our exclude list */
	for (ex = &rootfs_excludes[0]; *ex; ex++) {
		if (!strcmp(*ex, e->d_name))
			return;
	}

	use_stat = (lstat(path, &st) == 0);

	snprintf(newpath, PATH_MAX, "%s/%s", root_path, path);

	switch (e->d_type) {
	case DT_DIR:
		mkdir(newpath, 0755);
		break;
	case DT_REG:
		/*
		 * copy the file to its new location, but first
		 * check to see if we have a walnut-specific version
		 * in /system/etc/
		 */
		snprintf(linkpath, PATH_MAX, WALNUT_ETC_PATH "/%s", path);
		if (stat(linkpath, &walnut_st) == 0)
			path = linkpath;
		copy_file(path, newpath);
		break;
	case DT_LNK:
		memset(linkpath, 0, PATH_MAX);
		if (readlink(path, linkpath, PATH_MAX) < 0)
			break;
		symlink(linkpath, newpath);
		break;
	default:
		break;
	};

	if (use_stat) {
		chown(newpath, st.st_uid, st.st_gid);
		chmod(newpath, st.st_mode);
	}
}

/*
 * Setup a walnut's root file system
 */
static int mount_rootfs(const char *root_path)
{
	int ret = 0, fd;
	char pathbuf[PATH_MAX];

	if (!dir_exists(root_path)) {
		errno = ENOENT;
		return -1;
	}

	/*
	 * mount a tmpfs directory on 'root_path'
	 * this will be remounted read-only by init.walnut.rc in the new walnut
	 */
	if (!is_mounted(root_path))
		ret = mount("none", root_path, "tmpfs", 0, NULL);

	if (ret < 0)
		return ret;

	/*
	 * copy the directory structure of our own root dir
	 * (use a depth of 0 to avoid diving into directories)
	 */
	ret = walkdir((void *)root_path, "/", 0, copyfs_callback);
	ret += walkdir((void *)root_path, "/sbin", 100, copyfs_callback);
	ret += walkdir((void *)root_path, "/root", 100, copyfs_callback);
	if (ret) {
		umount(root_path);
		return ret;
	}

	return 0;
}

static int mount_datafs(const char *root_path, const char *rw_path)
{
	int ret, s_errno;
	/* Bind mount <walnut>/data to <walnut-rw>/data */
	char *data_dst = malloc(strlen(root_path)+16);
	if (!data_dst)
		return -1;
	sprintf(data_dst, "%s/data", root_path);
	char *data_src = malloc(strlen(rw_path)+16);
	if (!data_src) {
		free(data_dst);
		return -1;
	}
	sprintf(data_src, "%s/data", rw_path);

	ret = 0;
	if (is_mounted(data_dst))
		goto out;

	ALOGD("Bind mounting %s to %s", data_src, data_dst);
	ret = mount(data_src, data_dst, NULL, MS_BIND, NULL);
	s_errno = errno;
out:
	free(data_dst);
	free(data_src);
	if (ret < 0)
		errno = s_errno;
	return ret;
}

static int mount_systemfs(const char *root_path, const char *rw_path)
{
	int ret, s_errno;
	char *mount_opts = malloc(strlen(rw_path) + 64);
	if (mount_opts == NULL)
		return -1;
	sprintf(mount_opts, "br:%s/system=rw:/system=ro", rw_path);
	char *system_path = malloc(strlen(root_path)+16);
	if (system_path == NULL) {
		free(mount_opts);
		return -1;
	}
	sprintf(system_path, "%s/system", root_path);

	ret = 0;
	if (is_mounted(system_path))
		goto out;

	ALOGD("Performing aufs mount on %s: options='%s'",
	     system_path, mount_opts);
	ret = mount("none", system_path, "aufs", 0, mount_opts);
	s_errno = errno;
out:
	free(system_path);
	free(mount_opts);
	if (ret < 0)
		errno = s_errno;
	return ret;
}

static int mount_sdcard(const char *name, const char *root_path,
			const char *rw_path)
{
	int ret, s_errno;
	char *src, *dst;

	/* +10: '//sdcard0\0' */
	src = malloc(strlen(g_sdcard_root) + strlen(name) + 10);
	/* +13: '/mnt/storage\0' */
	dst = malloc(strlen(root_path) + 13);

	if (!src || !dst) {
		free(src);
		free(dst);
		return -1;
	}

	sprintf(src, "%s/%s/sdcard", g_sdcard_root, name);
	sprintf(dst, "%s/mnt/storage", root_path);

	ret = 0;
	if (is_mounted(dst))
		goto out;

	mkdir(dst, 0775); /* just to be sure */
	ALOGD("Bind mounting '%s' to '%s'", src, dst);
	ret = mount(src, dst, NULL, MS_BIND, NULL);
	s_errno = errno;
out:
	free(src);
	free(dst);
	if (ret < 0)
		errno = s_errno;
	return ret;
}

/* Mount a walnut's filesystem */
int mount_walnut(char *name, int sdcard_mnt)
{
	int ret = -1;
	char *root_path = get_root_path(name);
	if (root_path == NULL) {
		errno = -EINVAL;
		return -1;
	}

	char *rw_path = get_rw_path(name);
	if (rw_path == NULL) {
		errno = -ENOMEM;
		free(root_path);
		return -1;
	}

	if (mount_rootfs(root_path) < 0) {
		ALOGE("Failed to mount walnut's root dir");
		goto err_free_paths;
	}

	if (mount_datafs(root_path, rw_path) < 0) {
		ALOGE("Failed to mount walnut's data dir: %s", strerror(errno));
		goto err_free_paths;
	}

	if (mount_systemfs(root_path, rw_path) < 0) {
		ALOGE("Failed to mount walnut's system dir: %s", strerror(errno));
		goto err_free_paths;
	}

	if (sdcard_mnt && mount_sdcard(name, root_path, rw_path) < 0) {
		ALOGE("Failed to mount walnut's sdcard: %s", strerror(errno));
		goto err_free_paths;
	}
	ret = 0;

err_free_paths:
	free(rw_path);
	free(root_path);

	return ret;
}

/* construct a simple argv array mostly so I can use getopt()... */
static int construct_argv(char *options, char ***argv, int *argc)
{
	char *str, *opt;
	char *saveptr;

	*argv = malloc(sizeof(char *) * MAX_ARGS);
	if (!(*argv))
		return -1;
	(*argv)[0] = "__walnutd__";
	*argc = 1;
	for (str = options; *argc < MAX_ARGS; str = NULL) {
		opt = strtok_r(str, " ", &saveptr);
		if (opt == NULL)
			break;
		(*argv)[(*argc)++] = opt;
	}

	return 0;
}

/*
 * Constructs walnut start args from walnut_start_args
 * If the args differ from those in the walnut's config, updates config.
 *
 * If noopt is set in walnut_start_args, just load settings from config.
 */
static int get_walnut_args(char *name, struct walnut_args *walnut_args)
{
	struct walnut_start_args *args = &walnut_args->start_args;
	int len;
	struct config_info config;

	if (read_config(name, &config) == -1) {
		ALOGE("failed to read config for %s", name);
		return -1;
	}

	ALOGD("%s is %s new walnut\n", name, config.newwalnut ? "a" : "NOT a");
	if (args->noopt && !config.newwalnut) {
		/* Use options from config */
		ALOGI("start(%s): Using stored config option", name);
		config_to_start_args(&config, args);
	} else {
		/* Custom options */
		ALOGI("start(%s): Using custom options", name);
		start_args_to_config(args, &config);
		config.newwalnut = 0;

		/* Update config with new startopts */
		write_config(name, &config); /* (doesn't matter if it fails) */
	}

	/* Construct root_path for walnut */
	walnut_args->rootdir = get_root_path(name);
	if (!walnut_args->rootdir) {
		ALOGE("no memory for rooth_path!");
		return -1;
	}

	/* Remove possible trailing '/' from root_path */
	len = strlen(walnut_args->rootdir);
	if (walnut_args->rootdir[len - 1] == '/')
		walnut_args->rootdir[len - 1] = '\0';

	strcpy(walnut_args->walnutname, name);

	return 0;
}

static time_t tv_to_usec(struct timeval *tv)
{
	return tv->tv_usec + (1000000 * tv->tv_sec);
}

static void usec_to_tv(struct timeval *tv, time_t usec)
{
	tv->tv_sec  = usec / 1000000;
	tv->tv_usec = usec % 1000000;
}

static int finish_walnut_startup(char *name)
{
	int ret;
	struct timeval stop_time;
	time_t delta = 0;

	if (gettimeofday(&stop_time, NULL) == -1)
		ALOGE("gettimeofday(%s) failed: %s", name, strerror(errno));
	pthread_mutex_lock(&g_walnut_list.mutex);
	struct walnut_node *walnut = search_walnuts(name);
	if (walnut == NULL) {
		pthread_mutex_unlock(&g_walnut_list.mutex);
		return -1;
	}
	walnut->starting = 0;
	pthread_mutex_unlock(&g_walnut_list.mutex);

	delta = tv_to_usec(&stop_time) - tv_to_usec(&walnut->start_time);
	usec_to_tv(&stop_time, delta);
	ALOGI("start(%s) duration: %ld seconds %ld microsec",
	     name, stop_time.tv_sec, stop_time.tv_usec);
	return 0;
}

/* Monitors a named pipe inside a walnut. Waits for Launcher2 to send a message
 * that the walnut is ready. Updates starting state of walnut upon receipt.
 */
static void *__monitor_start_state(void *arg)
{
	int fd;
	fd_set rfds;
	struct timeval tv;
	int ret;
	char *pipe_name = NULL;
	char *root_path = NULL;
	char buf[20];

	/* Can't keep reference to walnut node if we're going to be thread safe */
	struct walnut_monitor_state *cms = (struct walnut_monitor_state *)arg;
	root_path = get_root_path(cms->name);

	ALOGI("Waiting for '%s' to initialize...", cms->name);
	ret = read(cms->child_fd, buf, 1);
	if (ret == -1 || buf[0] != 1)
		ALOGE("Error waiting for '%s' initialization", cms->name);

	/* Create named pipe for Launcher2 to tell us walnut is ready via */
/*	pipe_name = (char *)malloc(PATH_MAX);
	if (!pipe_name)
		goto __monitor_start_state_err;
	memset(pipe_name, 0, PATH_MAX);

	snprintf(pipe_name, PATH_MAX, "%s/dev/walnutd.startpipe", root_path);
	unlink(pipe_name);
	if (mkfifo(pipe_name, 0666) < 0) {
		ALOGE("Failed to create pipe for start state update");
		goto __monitor_start_state_err;
	}*/

	/* Unblock the new walnut and wait for it to start up */
	snprintf(buf, sizeof(buf), "%d", cms->pid);
	write(cms->init_fd, buf, strlen(buf) + 1);
	close(cms->init_fd);
/*
	fd = open(pipe_name, O_RDWR);
	if (fd == -1) {
		ALOGE("Cannot open start pipe");
		unlink(pipe_name);
		goto __monitor_start_state_err;
	}

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
*/
	/* Wait up to ten minutes - this way we can just terminate ourselves
	   if something went wrong and this thread doesn't have to be tracked */
/*	tv.tv_sec = 600;
	tv.tv_usec = 0;

	ALOGI("Waiting on for '%s' to start...", cms->name);
	ret = select(fd+1, &rfds, NULL, NULL, &tv);
	if (ret == -1)
		ALOGE("select() on start pipe failed");
	else if (ret)
		finish_walnut_startup(cms->name);
	close(fd);
	unlink(pipe_name);
*/
	finish_walnut_startup(cms->name);
	ALOGI("Cell '%s' started!", cms->name);

	free(cms);
	free(pipe_name);
	free(root_path);

	return (void *)0;

__monitor_start_state_err:
	finish_walnut_startup(cms->name);
	free(cms);
	free(pipe_name);
	free(root_path);
	return (void *)-1;
}

static void monitor_start_state(struct walnut_node *walnut, int pid,
				int child_fd, int init_fd)
{
	pthread_t tid;
	struct walnut_monitor_state *cms;

	/* we can't trust that walnut will still exist so copy name out of it */
	cms = (struct walnut_monitor_state *)malloc(sizeof(*cms));
	if (!cms)
		return;
	memset(cms, 0, sizeof(*cms));

	strncpy(cms->name, walnut->name, MAX_NAME_LEN);
	cms->pid = pid;
	cms->child_fd = child_fd;
	cms->init_fd = init_fd;
	if (pthread_create(&tid, NULL, __monitor_start_state, (void *)cms) < 0) {
		char buf[20];
		ALOGE("NOT monitoring startup state of walnut!");
		snprintf(buf, sizeof(buf), "%d", pid);
		write(init_fd, buf, strlen(buf)+1);
		close(init_fd);
		close(child_fd);
	} else {
		ALOGI("thread %d monitoring start %s(%d) state",
		      (int)__pthread_gettid(tid), cms->name, cms->pid);
	}
}

/* Creates root_path and rw_path directories if they don't already exist */
/* If (warn) this will ALOGW directory creation */
static int create_walnut_dirs(char *name, int warn)
{
	/* directories that I need to create in the r/w path
	 * to work around aufs quirks (two write branches, one on a vfat)
	 */
	static const char *rwdirs[] = {
		"mnt", "mnt/storage",
		"data", "data/app", "data/property",
		"system",
		NULL
	};
	const char *pdir;
	char dpath[255];
	int i;

	char *root_path = get_root_path(name);
	if (root_path == NULL)
		return -1;

	/* Create mount point for container if it doesn't exist */
	if (!dir_exists(root_path)) {
		if (warn)
			ALOGW("Had to mkdir %s\n", root_path);
		if (mkdir(root_path, 0750) == -1) {
			ALOGE("mkdir %s failed: %s", root_path, strerror(errno));
			free(root_path);
			return -1;
		}
	}

	char *rw_path = get_rw_path(name);
	if (rw_path == NULL)
		return -1;

	/* Create read write folder for container */
	if (!dir_exists(rw_path)) {
		if (warn)
			ALOGW("Had to mkdir %s\n", rw_path);
		if (mkdir(rw_path, 0750) == -1) {
			ALOGE("mkdir %s failed: %s", rw_path, strerror(errno));
			free(rw_path);
			rmdir(root_path);
			free(root_path);
			return -1;
		}
	}

	/* make a couple directories in rw path to work around aufs quirks */
	for (i = 0, pdir=rwdirs[0]; pdir; i++, pdir = rwdirs[i]) {
		snprintf(dpath, sizeof(dpath), "%s/%s", rw_path, pdir);
		if (mkdir(dpath, 0755) == -1 && errno != EEXIST)
			ALOGE("mkdir %s failed(%d): %s", dpath, errno,
			     strerror(errno));
	}

	/* attempt to ensure that the bind-mounted sdcard directory will be
	 * there when we need it - we can ignore errors from this call because
	 * it's up to the caller whether or not to enable the bind mount in
	 * the first place.
	 */
	mkdir(g_sdcard_root, 0775);
	snprintf(dpath, sizeof(dpath), "%s/%s", g_sdcard_root, name);
	mkdir(dpath, 0775);
	snprintf(dpath, sizeof(dpath), "%s/%s/sdcard", g_sdcard_root, name);
	mkdir(dpath, 0775);

	free(root_path);
	free(rw_path);
	return 0;
}

/*
 * Unlocks the config_lock and then sends the message
 * (Don't perform a blocking call with a mutex held )
 */
static int unlock_send_msg(pthread_mutex_t *mtx, int fd, char *fmt, ...)
{
	int ret;
	va_list ap;

	pthread_mutex_unlock(mtx);

	va_start(ap, fmt);
	ret = _send_msg(fd, fmt, ap);
	va_end(ap);

	return ret;
}


/* Lists all created walnuts and their current status */
#define WALNUT_STOPPED	0x01
#define WALNUT_ZOMBIE	0x02
#define WALNUT_STARTING	0x04
#define WALNUT_ACTIVE	0x08
#define WALNUT_RUNNING	0x10
#define WALNUT_RUNNING_MASK (WALNUT_STARTING | WALNUT_ACTIVE | WALNUT_RUNNING)

static char *status_to_name(int status)
{
	switch (status) {
	case WALNUT_STOPPED:	return "";
	case WALNUT_ZOMBIE:	return "zombie";
	case WALNUT_STARTING:	return "starting";
	case WALNUT_ACTIVE:	return "active";
	case WALNUT_RUNNING:	return "running";
	default:		return "unknown";
	}
}

static void list_walnuts(int fd, int mask)
{
	int i, n, s;
	struct walnut_node *walnut;
	char **name_list;
	char *init_pid;
	char msg[MAX_MSG_LEN];
	msg[0] = '\0'; /* In case walnut list is empty */
	char *cur = msg;
	int n_avail = MAX_MSG_LEN;

	name_list = get_walnut_names();
	if (name_list == NULL) {
		send_msg(fd, "1 Failed to get name list");
		return;
	}

	for (i = 0; name_list[i] != NULL; ++i) {
		walnut = search_walnuts(name_list[i]);
		if (!walnut && !search_dead_walnuts(name_list[i]))
			s = WALNUT_STOPPED;
		else if (!walnut)
			s = WALNUT_ZOMBIE;
		else if (walnut->starting)
			s = WALNUT_STARTING;
		else if (walnut == active_walnut)
			s = WALNUT_ACTIVE;
		else
			s = WALNUT_RUNNING;

		if (s & mask && s & WALNUT_RUNNING_MASK) {
			n = snprintf(cur, n_avail, "%s\31%s\31%i\30",
				     name_list[i], status_to_name(s),
				     walnut->init_pid);
		} else if (s & mask) {
			n = snprintf(cur, n_avail, "%s\31%s\30",
				     name_list[i], status_to_name(s));
		} else {
			ALOGE("Unknown state!");
			n = 0;
		}

		n_avail -= n;
		cur += n;
		if (n_avail <= 0)
			break;
	}
	free_walnut_names(name_list);
	send_msg(fd, "0 %s", msg);
}

/* Sends back a msg with info for each walnut separated by the record separator
 * (\30) and each field of info separated by the unit separator (\31) */
static void do_list(int fd, struct walnut_cmd_arg *cmd_args)
{
	struct walnut_list_args *args = &cmd_args->list_args;
	int mask = 0;

	if (args->all)
		mask = ~0;
	else if (args->running)
		mask = WALNUT_RUNNING_MASK;
	else if (args->zombie)
		mask = WALNUT_ZOMBIE;
	list_walnuts(fd, mask);
}

static void write_token_state(char *filename, char *buf)
{
	FILE *fd_out = fopen(filename, "w");
	if (fd_out == NULL) {
		ALOGE("wifi: failed to open %s", filename);
	}
	fwrite(buf, 1, 1, fd_out);
	fflush(fd_out);
	fclose(fd_out);
}

static void *token_record_listener(void *data)
{
	struct walnut_node *walnut = (struct walnut_node *)active_walnut;
	char *root_path;
	char *filename;
	char buf[] = {0};
	char **name_list;
	int i = 0;

	name_list = get_walnut_names();
	if (name_list == NULL) {
		return (void *)-1;
	}
	if (walnut == NULL) {
		return (void *)-1;
	}
	filename = (char *)malloc(PATH_MAX);
	root_path = get_root_path(walnut->name);
	snprintf(filename, PATH_MAX, "%s/data/whoareyou", root_path);
	buf[0] = 0xaa;
	write_token_state(filename, buf);

	for (i = 0; name_list[i] != NULL; ++i) {
		walnut = search_walnuts(name_list[i]);
		if (walnut == active_walnut || walnut == NULL) {
			continue;
		}
		root_path = get_root_path(walnut->name);
		if (root_path == NULL) {
			ALOGE("wifi: got null root_path");
			return NULL;
		}
		snprintf(filename, PATH_MAX, "%s/data/whoareyou", root_path);
		ALOGD("wifi: filename %s", filename);
		buf[0] = 0;
		write_token_state(filename, buf);
	}

	free(filename);
	free(root_path);
	free_walnut_names(name_list);
	ALOGD("wifi listener OK");
	return NULL;
}

static void create_token_record_listener(struct walnut_node *walnut)
{
	pthread_t tid;
	pthread_create(&tid, NULL, token_record_listener, NULL);
}

/*
 * 0 on success,
 * -code on error
 */
int __do_switch(struct walnut_node *walnut)
{
	char buf[64];
	int proc_fd;

	if (!walnut)
		return -1;

	/* Perform the switch by writing to active_ns_pid */
	proc_fd = open("/proc/dev_ns/active_ns_pid", O_WRONLY);
	if (proc_fd == -1) {
		ALOGE("Failed to open active_ns_pid: %s", strerror(errno));
		return -1;
	}

	/* Make sure specified walnut is not already active */
	pthread_mutex_lock(&active_walnut_lock);
	if (walnut == active_walnut) {
		pthread_mutex_unlock(&active_walnut_lock);
		close(proc_fd);
		return -2;
	}

	/* Do the switch */
	snprintf(buf, sizeof(buf), "%d", walnut->init_pid);
	if (write(proc_fd, buf, strnlen(buf, sizeof(buf))) == -1) {
		ALOGE("Failed to write to active_ns_pid: %s", strerror(errno));
		close(proc_fd);
		pthread_mutex_unlock(&active_walnut_lock);
		return -3;
	}

	close(proc_fd);

	active_walnut = walnut;
	pthread_mutex_unlock(&active_walnut_lock);
//	create_token_record_listener(walnut);
	return 0;
}

/* Attempts to switch to the next running walnut started after the active walnut */
void switch_to_next(void)
{
	ALOGI("(switch to next): Looking for 'next' walnut");
	struct walnut_node *walnut;
	pthread_mutex_lock(&g_walnut_list.mutex);
	walnut = get_next_walnut(active_walnut);
	if (walnut)
		ALOGI("(next) Switching to '%s'", walnut->name);
	(void)__do_switch(walnut);
out:
	pthread_mutex_unlock(&g_walnut_list.mutex);
}

/* Send response message back after __do_switch */
static void switch_response(int fd, int ret, char *name)
{
	switch (ret) {
	case -1:
		send_msg(fd, "1 Switch failed. Couldn't open proc file");
		break;
	case -2:
		send_msg(fd, "1 Cell is already active");
		break;
	case -3:
		send_msg(fd, "1 Switch failed. Couldn't write to proc file");
		break;
	}

	/* Send success response */
	send_msg(fd, "0 Switched to %s", name);
}

/* Perform the next and prev commands. Set next to true if performing next. */
static void __do_next_or_prev(int fd, int next)
{
	int ret;
	struct walnut_node *orig = active_walnut;
	struct walnut_node *walnut = orig;
	pthread_mutex_lock(&g_walnut_list.mutex);
	/* Loop until we've exhausted the list or we've found a running walnut */
	do {
		if (next)
			walnut = get_next_walnut(walnut);
		else
			walnut = get_prev_walnut(walnut);
	} while (walnut != NULL && walnut != orig && walnut->starting);

	if (walnut == NULL)
		walnut = g_walnut_list.head;

	if (walnut == NULL) {
		unlock_send_msg(&g_walnut_list.mutex, fd,
				"1 There are no running walnuts");
		return;
	}

	if (walnut == orig) {
		unlock_send_msg(&g_walnut_list.mutex, fd,
				"1 Only one walnut running");
		return;
	}

	ALOGI("(%s) Switching to '%s'", next ? "next" : "prev", walnut->name);
	ret = __do_switch(walnut);
	pthread_mutex_unlock(&g_walnut_list.mutex);

	switch_response(fd, ret, walnut->name);
}

/* Helper functions for prev and next commands */
static void do_next(int fd) {
	ALOGI("next: Attempting to switch to next walnut");
	__do_next_or_prev(fd, 1);
}
static void do_prev(int fd) {
	ALOGI("prev: Attempting to switch to previous walnut");
	__do_next_or_prev(fd, 0);
}

static void do_switch(int fd, struct walnut_cmd_arg *args)
{
	char *name = args->walnutname;

	int ret;
	pthread_mutex_lock(&g_walnut_list.mutex);
	struct walnut_node *walnut = search_walnuts(name);
	if (walnut == NULL) { /* Make sure walnut is running */
		unlock_send_msg(&g_walnut_list.mutex, fd,
				"1 Switch failed. Given walnut not running");
		return;
	}
	ALOGI("(switch) Switching to '%s'", name);
	ret = __do_switch(walnut);
	pthread_mutex_unlock(&g_walnut_list.mutex);

	if (args->cmd == WALNUT_SWITCH)
		switch_response(fd, ret, name);
}

static void do_getactive(int fd, struct walnut_cmd_arg *cmd_args)
{
	struct walnut_node *walnut;
	char name[MAX_NAME_LEN];

	name[0] = '\0';
	pthread_mutex_lock(&active_walnut_lock);
	walnut = active_walnut;
	if (walnut)
		strcpy(name, walnut->name);
	pthread_mutex_unlock(&active_walnut_lock);

	if (walnut != NULL)
		send_msg(fd, "0 %s", name);
	else
		send_msg(fd, "1 No walnut is active");
}

/* Creates a new walnut. "Creation" consists only of making 2 directories.
 * This func is used largely for design reasons and error checking. I don't
 * think you should be able to start a walnut you've never explicity made. */
static int __do_create(int fd, struct walnut_cmd_arg *cmd_args)
{
	struct walnut_create_args *args = &cmd_args->create_args;
	char *name = cmd_args->walnutname;
	struct config_info config;

	if (strcmp(cmd_args->walnutname, "") == 0) {
		send_msg(fd, "1 You must specify a walnut");
		return -1;
	}

	pthread_mutex_lock(&config_lock);

	if (walnut_exists(name)) {
		unlock_send_msg(&config_lock, fd,
				"1 Create failed. Given name already exists.");
		return -1;
	}

	if (args->id > -1 && id_exists(args->id)) {
		unlock_send_msg(&config_lock, fd,
				"1 Create failed. ID already exists.");
		return -1;
	}

	init_config(&config);
	if (args->id != -1)
		config.id = args->id;
	if (write_config(cmd_args->walnutname, &config) == -1) {
		unlock_send_msg(&config_lock, fd,
				"1 Create failed. Couldn't create config file.");
		return -1;
	}

	if (create_walnut_dirs(cmd_args->walnutname, 0) == -1) {
		unlock_send_msg(&config_lock, fd,
				"1 Create failed. Couldn't create directories");
		remove_config(cmd_args->walnutname);
		return -1;
	}

	pthread_mutex_unlock(&config_lock);
	return 0;
}

static void do_create(int fd, struct walnut_cmd_arg *cmd_args)
{
	int ret = __do_create(fd, cmd_args);
	if (ret == 0)
		send_msg(fd, "0 Created %s", cmd_args->walnutname);
}

/* Returns the newly created walnut_node on success. NULL on failure */
static struct walnut_node *__do_start(int fd, char *name,
				    struct walnut_start_args *args)
{
	int pid = -1;
	int config_ret, proc_fd;
	struct config_info config;
	struct walnut_node *new;
	struct pty_info console_pty;

	struct walnut_args walnut_args;
	memcpy(&walnut_args.start_args, args, sizeof(walnut_args.start_args));

	if (get_walnut_args(name, &walnut_args) == -1) {
		send_msg(fd, "1 Start failed. Error parsing start options");
		return NULL;
	}

	/*
	 * Allocates argv on struct walnut_args and sets to /init
	 */
	walnut_args.argv = malloc(sizeof(char *)*2);
	if (!walnut_args.argv) {
		ALOGE("No memory for walnut argv");
		send_msg(fd, "1 Start failed. No memory for walnut argv");
		return NULL;
	}
	walnut_args.argv[0] = "/init";
	walnut_args.argv[1] = NULL;
	walnut_args.argc = 1;

	/*
	 * Start init in new namespace
	 */
	pid = walnut_nsexec(fd, &walnut_args, name, &console_pty);

	free(walnut_args.argv);

	if (pid == -1) {
		/* nsexec() already sent and logged an error message. It
		 * will have also cleaned up after itself on an error */
		return NULL;
	}

	/* Try our best to update the config file. Not fatal if we fail. */
	config_ret = read_config(name, &config);
	config.initpid = pid;
	if (config_ret != -1)
		write_config(name, &config);

	/* Create a new node and add it to walnuts list */
	new = create_walnut_node(name, &config, &console_pty);
	if (new == NULL) {
		/*
		 * we have to manually clean up a few things b/c we couldn't
		 * add this walnut to a list!
		 */
		kill(pid, SIGKILL); /* walnut's parent will handle rest */
		tear_down_walnut(&walnut_args, &console_pty);
		send_msg(fd, "1 Start failed. Couldn't create walnut node (this is really bad)");
		return NULL;
	}
	new->start_time = walnut_args.start_time;

	/* set the tag name for the newly created device namespace */
	proc_fd = open("/proc/dev_ns/ns_tag", O_WRONLY);
	if (proc_fd >= 0) {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d:%s", pid, name);
		if (write(proc_fd, buf, strnlen(buf, sizeof(buf))) == -1)
			ALOGW("Failed to set tag for %s (pid:%d)", name, pid);
		close(proc_fd);
	}

	add_walnut_node(new);

	if (walnut_args.start_args.autoswitch) {
		ALOGI("(startup) Switching to '%s'", name);
		__do_switch(new);
	}

	monitor_start_state(new, pid,
			    walnut_args.child_pipe[0],
			    walnut_args.init_pipe[1]);

	return new;
}

static void do_start(int fd, struct walnut_cmd_arg *cmd_args)
{
	struct walnut_start_args *args = &cmd_args->start_args;
	char *name = cmd_args->walnutname;

	struct walnut_node *ret;

	ALOGI("start: Start %s\n", name);
	if (strcmp(name, "") == 0) {
		send_msg(fd, "1 You must specify a walnut");
		return;
	}

	/* Make sure walnut exists */
	pthread_mutex_lock(&config_lock);
	if (!walnut_exists(name)) {
		unlock_send_msg(&config_lock, fd,
				"1 Start failed. Cell does not exist.");
		return;
	}
	/* Make sure walnut is not already running */
	if (search_walnuts(name) != NULL) {
		unlock_send_msg(&config_lock, fd,
				"1 Start failed. Cell is already running.");
		return;
	}

	/* Make sure the walnut's directories exist */
	if (create_walnut_dirs(name, 1) == -1) {
		unlock_send_msg(&config_lock, fd,
				"1 Start failed. Could not create walnut dirs.");
		return;
	}

	ret = __do_start(fd, name, args);
	pthread_mutex_unlock(&config_lock);

	/*
	 * __do_start already sent and logged an error message.
	 * It will have also clean up after itself on an error
	 */
	if (ret == NULL)
		return;

	if (args->wait) {
		ALOGI("walnut client is waiting for '%s'...", name);
		while (ret->starting)
			sleep(1);
	}

	send_msg(fd, "0 Started %s", name);
}

static void do_stop(int fd, struct walnut_cmd_arg *cmd_args)
{
	char *name = cmd_args->walnutname;
	ALOGI("stop: Stop %s", name);
	if (strcmp(name, "") == 0) {
		send_msg(fd, "1 You must specify a walnut");
		return;
	}

	pthread_mutex_lock(&g_walnut_list.mutex);
	struct walnut_node *walnut = search_walnuts(name);
	if (walnut == NULL) {
		unlock_send_msg(&g_walnut_list.mutex, fd,
				"1 Cell, %s, is not running", name);
		return;
	}

	char *root_path = get_root_path(name);
	if (root_path == NULL) {
		unlock_send_msg(&g_walnut_list.mutex, fd,
				"1 Stop failed. Could not get root path.");
		return;
	}

	pthread_mutex_lock(&active_walnut_lock);
	if (walnut == active_walnut)
		active_walnut = NULL;
	pthread_mutex_unlock(&active_walnut_lock);

	/*
	if (walnut->RIL_PROXY) {
		CLEANUP RIL PROXY SOCKET
	}
	 */

	/* Remove walnut from list */
	mark_walnut_deleted(walnut);
	pthread_mutex_unlock(&g_walnut_list.mutex);

	/* kill the init process */
	kill(walnut->init_pid, SIGKILL);

	/*
	 * if we re-attached to this walnut, then it's init process is not one
	 * of our children, and we have to do some manual cleanup work,
	 * otherwise our SIGCHLD handler will complete the cleanup.
	 */
	if (walnut->non_child)
		walnut_cleanup_and_free(walnut, root_path, &g_dead_walnut_list);

	free(root_path);

	send_msg(fd, "0 Stopped %s", name);
}

static void do_destroy(int fd, struct walnut_cmd_arg *cmd_args)
{
	char *name = cmd_args->walnutname;

	ALOGI("stop: Destroy %s", name);
	if (strcmp(name, "") == 0) {
		send_msg(fd, "1 You must specify a walnut");
		return;
	}

	pthread_mutex_lock(&config_lock);

	/* Make sure walnut exists */
	if (!walnut_exists(name)) {
		unlock_send_msg(&config_lock, fd,
				"1 Destroy failed. Cell does not exist.");
		return;
	}

	/* Make sure walnut is not currently running */
	if (search_walnuts(name) != NULL) {
		unlock_send_msg(&config_lock, fd,
				"1 Destroy failed. Cell is currently running.");
		return;
	}

	/* Get the paths to remove */
	char *root_path = get_root_path(name);
	if (root_path == NULL) {
		unlock_send_msg(&config_lock, fd,
				"1 Destroy failed. Could not get root path.");
		return;
	}
	char *rw_path = get_rw_path(name);
	if (rw_path == NULL) {
		unlock_send_msg(&config_lock, fd,
				"1 Destroy failed. Could not get rw path.");
		goto err_free_rootpath;
	}

	/* Remove the walnut's files */
	if (dir_exists(rw_path)) {
		if (rmtree(rw_path) == -1) {
			unlock_send_msg(&config_lock, fd,
					"1 Could not remove rw path.");
			goto err_free_path;
		}
	}
	if (dir_exists(root_path)) {
		if (rmtree(root_path) == -1) {
			unlock_send_msg(&config_lock, fd,
					"1 Could not remove root path.");
			/*
			 * we've already removed the rw_path, so we'll
			 * error out, but first let's at least make it
			 * runnable again
			 */
			create_walnut_dirs(name, 0);
			goto err_free_path;
		}
	}

	/* Remove config */
	if (remove_config(name) == -1) {
		create_walnut_dirs(name, 0);
		unlock_send_msg(&config_lock, fd,
				"1 Could not remove config file.");
		goto err_free_path;
	}

	unlock_send_msg(&config_lock, fd, "0 Destroyed %s", name);

err_free_path:
	free(rw_path);
err_free_rootpath:
	free(root_path);
}

/* Sends back the fd associated with a walnut's console */
static void do_console(int fd, struct walnut_cmd_arg *args)
{
	char *code, *rmsg;
	char *name = args->walnutname;
	char *msg;
	if (strcmp(name, "") == 0) {
		send_msg(fd,"1 Failed to get console. You must specify a walnut");
		return;
	}

	ALOGI("console: Console requested for %s", name);

	pthread_mutex_lock(&g_walnut_list.mutex);
	struct walnut_node *walnut = search_walnuts(name);
	if (walnut == NULL) {
		send_msg(fd, "1 Cell is not running");
		goto err_do_console;
	} else if (walnut->console_pty.ptm == -1) {
		send_msg(fd, "1 Console unavailable for given walnut");
		goto err_do_console;
	}

	/* Console avaiable. Send success msg followed by fd */
	if (send_msg(fd, "0 %s", CONSOLE_READY_MSG) == -1) {
		ALOGE("Error sending console message");
		goto err_do_console;
	}

	/*
	 * We do this extra hand-shake so the recv_msg (in walnut utility)
	 * on the send_msg above doesn't eat the console file descriptor.
	 */
	if (recv_msg_len(fd, &code, &rmsg, CONSOLE_READY_MSG_LEN) < 0) {
		ALOGE("Error receiving ready message");
		goto err_do_console;
	}

	if (send_fd(fd, walnut->console_pty.ptm) == -1)
		ALOGE("Failed to send console file descriptor: %s",
		     strerror(errno));

err_do_console:
	ALOGI("Finished console for %s", name);
	pthread_mutex_unlock(&g_walnut_list.mutex);
}

static void do_mount(int fd, struct walnut_cmd_arg *cmd_args)
{
	struct walnut_mount_args *args = &cmd_args->mount_args;
	char *name = cmd_args->walnutname;

	ALOGI("mount: Mount request for \"%s\"", name);
	if (strcmp(name, "") == 0) {
		send_msg(fd, "1 Failed to mount. You must specify a walnut");
		return;
	}

	/* Mount the filesystem */
	if (mount_walnut(name, args->all) == -1) {
		send_msg(fd, "1 Failed to mount filesystem for walnut");
		return;
	}
	send_msg(fd, "0 Mounted filesystem at %s/%s", g_walnut_dir, name);
}

int unmount_all(const char *root_path, int free_root)
{
	int root_path_len;
	char *mtpoint;
	int ret = 0;

	ALOGD("%s: unmounting %s (and all sub-mounts)", __func__, root_path);
	root_path_len = strlen(root_path) + 1;

	mtpoint = malloc(root_path_len);
	if (mtpoint == NULL)
		return -1;

	/* Play with pointers to save some typing */
	strcpy(mtpoint, root_path);
	if (mtpoint[root_path_len-2] == '/') {
		mtpoint[root_path_len-2] = '\0';
		root_path_len -= 1;
	}

	ret += __unmount_dir(mtpoint, "data/dalvik-cache");
	ret += __unmount_dir(mtpoint, "dev");
	ret += __unmount_dir(mtpoint, "mnt/asec");
	ret += __unmount_dir(mtpoint, "mnt/obb");
	ret += __unmount_dir(mtpoint, "mnt/secure");
	ret += __unmount_dir(mtpoint, "mnt");
	ret += __unmount_dir(mtpoint, "sys");
	ret += __unmount_dir(mtpoint, "proc");
	ret += __unmount_dir(mtpoint, "acct");

	if (free_root)
		ret += umount2(mtpoint, MNT_DETACH);
	free(mtpoint);
	return ret;
}

static void do_unmount(int fd, struct walnut_cmd_arg *cmd_args)
{
	char *name = cmd_args->walnutname;
	int ret;

	ALOGI("unmount: Unmounting request for \"%s\"", name);
	if (strcmp(name, "") == 0) {
		send_msg(fd, "1 Unmount failed. You must specify a walnut");
		return;
	}

	/* lock to prevent starting a walnut while we're mounting */
	pthread_mutex_lock(&config_lock);
	if (search_walnuts(name) != NULL) {
		unlock_send_msg(&config_lock, fd,
				"1 Unmount failed. Cell is currently running.");
		return;
	}

	char *root_path = get_root_path(name);
	if (root_path == NULL) {
		unlock_send_msg(&config_lock, fd,
				"1 Failed to find rootfs for %s", name);
		return;
	}

	ret = unmount_all(root_path, 1);

	if (ret != 0)
		unlock_send_msg(&config_lock, fd,
				"1 Failed to unmount rootfs %s (ret=%d)",
				root_path, ret);
	else
		unlock_send_msg(&config_lock, fd,
				"0 Unmounted filesystem at %s", root_path);

	free(root_path);
}

static void do_runcmd(int fd, struct walnut_cmd_arg *cmd_args)
{
	struct walnut_runcmd_args *args = &cmd_args->runcmd_args;
	char *name = cmd_args->walnutname;
	struct walnut_node *walnut;
	char *code, *rmsg;
	int cmdlen;

	ALOGI("Running command \"%s\" in \"%s\"", args->cmd, name);
	if (strcmp(name, "") == 0) {
		send_msg(fd, "1 logcat failed. You must specify a walnut");
		return;
	}
	cmdlen = strnlen(args->cmd, sizeof(args->cmd));
	if (cmdlen == 0 || args->cmd[0] == 0) {
		send_msg(fd, "1 invalid command.");
		return;
	}

	pthread_mutex_lock(&g_walnut_list.mutex);
	walnut = search_walnuts(name);
	if (walnut == NULL) {
		send_msg(fd, "1 Cell is not running");
		goto err;
	} else if (walnut->console_pty.ptm == -1) {
		send_msg(fd, "1 Console unavailable for given walnut");
		goto err;
	}

	if (send_msg(fd, "0 %s L %4d%s",
		     CONSOLE_READY_MSG, cmdlen+1, args->cmd) == -1) {
		ALOGE("Error sending command");
		goto err;
	}

	/*
	 * We do this extra hand-shake so the recv_msg (in walnut utility)
	 * on the send_msg above doesn't eat the console file descriptor.
	 */
	if (recv_msg_len(fd, &code, &rmsg, CONSOLE_READY_MSG_LEN) < 0) {
		ALOGE("Error receiving console ready message");
		goto err;
	}

	if (send_fd(fd, walnut->console_pty.ptm) == -1)
		ALOGE("Failed to send console file descriptor: %s",
		     strerror(errno));

err:
	pthread_mutex_unlock(&g_walnut_list.mutex);
}

static void do_autostart(int fd, struct walnut_cmd_arg *cmd_args)
{
	struct walnut_autostart_args *args = &cmd_args->autostart_args;
	char *name = cmd_args->walnutname;
	struct config_info config;

	if (strcmp(name, "") == 0) {
		send_msg(fd, "1 You must specify a walnut");
		return;
	}
	/* Make sure walnut exists */
	pthread_mutex_lock(&config_lock);
	if (!walnut_exists(name)) {
		unlock_send_msg(&config_lock, fd,
				"1 Cell, %s, does not exist", name);
		return;
	}

	if (read_config(name, &config) == -1) {
		unlock_send_msg(&config_lock, fd,
				"1 Could not read configuration file");
		return;
	}

	if (args->on)
		config.autostart = 1;
	else if (args->off) /* off */
		config.autostart = 0;
	else {
		unlock_send_msg(&config_lock, fd, "0 Cell autostart is %s",
				config.autostart ? "on" : "off");
		return;
	}

	ALOGI("autostart: Configure autostart for %s\n", name);

	if (write_config(name, &config) == -1) {
		unlock_send_msg(&config_lock, fd,
				"1 Could not write configuration file");
		return;
	}
	unlock_send_msg(&config_lock, fd, "0 Cell autostart %s",
			config.autostart ? "enabled" : "disabled");
}

static void do_autoswitch(int fd, struct walnut_cmd_arg *cmd_args)
{
	struct walnut_autostart_args *args = &cmd_args->autostart_args;
	char *name = cmd_args->walnutname;
	struct config_info config;

	if (strcmp(name, "") == 0) {
		send_msg(fd, "1 You must specify a walnut");
		return;
	}
	/* Make sure walnut exists */
	pthread_mutex_lock(&config_lock);
	if (!walnut_exists(name)) {
		unlock_send_msg(&config_lock, fd,
				"1 Cell '%s' does not exist", name);
		return;
	}

	if (read_config(name, &config) == -1) {
		unlock_send_msg(&config_lock, fd,
				"1 Could not read configuration file");
		return;
	}

	if (args->on)
		config.autoswitch = 1;
	else if (args->off) /* off */
		config.autoswitch = 0;
	else {
		unlock_send_msg(&config_lock, fd, "0 Cell autoswitch is %s",
				config.autoswitch ? "on" : "off");
		return;
	}

	ALOGI("autoswitch: Configure autoswitch for %s\n", name);

	if (write_config(name, &config) == -1) {
		unlock_send_msg(&config_lock, fd,
				"1 Could not write configuration file");
		return;
	}
	unlock_send_msg(&config_lock, fd, "0 Cell autoswitch %s",
			config.autoswitch ? "enabled" : "disabled");
}

static void do_setid(int fd, struct walnut_cmd_arg *cmd_args)
{
	char *name = cmd_args->walnutname;
	int id = cmd_args->setid_args.id;
	struct config_info config;
	struct walnut_node *walnut;

	ALOGI("setid: Set ID of %s", name);
	if (strcmp(name, "") == 0) {
		send_msg(fd, "1 You must specify a walnut");
		return;
	}

	/* Make sure walnut exists */
	pthread_mutex_lock(&config_lock);
	if (!walnut_exists(name)) {
		unlock_send_msg(&config_lock, fd,
				"1 Setting ID failed. Cell does not exist.");
		return;
	}

	if (id < 0 || id > 9) {
		unlock_send_msg(&config_lock, fd,
				"1 Invalid ID given. Expecting 0-9.");
		return;
	}
	if (id_exists(id)) {
		unlock_send_msg(&config_lock, fd,
				"1 ID is already in use.");
		return;
	}
	if (read_config(name, &config) == -1) {
		unlock_send_msg(&config_lock, fd,
				"1 Failed to read configuration file.");
		return;
	}
	config.id = id;
	if (write_config(name, &config) == -1) {
		unlock_send_msg(&config_lock, fd,
				"1 Failed to write configuration file.");
		return;
	}

	/* Update running ID if walnut is running */
	pthread_mutex_lock(&g_walnut_list.mutex);
	walnut = search_walnuts(name);
	if (walnut != NULL)
		walnut->id = id;
	pthread_mutex_unlock(&g_walnut_list.mutex);

	unlock_send_msg(&config_lock, fd, "0 Changed %s's ID to %d", name, id);
}

static void do_getid(int fd, struct walnut_cmd_arg *cmd_args)
{
	char *name = cmd_args->walnutname;
	struct config_info config;
	ALOGI("getid: Get ID of %s", name);
	if (strcmp(name, "") == 0) {
		send_msg(fd, "1 You must specify a walnut");
		return;
	}
	/* Make sure walnut exists */
	pthread_mutex_unlock(&config_lock);
	if (!walnut_exists(name)) {
		unlock_send_msg(&config_lock, fd,
				"1 Getting ID failed. Cell does not exist.");
		return;
	}
	if (read_config(name, &config) == -1) {
		unlock_send_msg(&config_lock, fd,
				"1 Failed to read configuration file.");
		return;
	}
	unlock_send_msg(&config_lock, fd, "0 %d", config.id);
}

static void dispatch_walnut_cmd(int fd, struct walnut_cmd_arg *arg)
{
	switch (arg->cmd) {
	case WALNUT_CREATE:	do_create(fd, arg);	break;
	case WALNUT_DESTROY:	do_destroy(fd, arg);	break;
	case WALNUT_LIST:		do_list(fd, arg);	break;
	case WALNUT_NEXT:		do_next(fd);		break;
	case WALNUT_PREV:		do_prev(fd);		break;
	case WALNUT_START:	do_start(fd, arg);	break;
	case WALNUT_STOP:		do_stop(fd, arg);	break;
	case WALNUT_SWITCH:	do_switch(fd, arg);	break;
	case WALNUT_CONSOLE:	do_console(fd, arg);	break;
	case WALNUT_AUTOSTART:	do_autostart(fd, arg);	break;
	case WALNUT_AUTOSWITCH:	do_autoswitch(fd, arg);	break;
	case WALNUT_GETID:	do_getid(fd, arg);	break;
	case WALNUT_SETID:	do_setid(fd, arg);	break;
	case WALNUT_GETACTIVE:	do_getactive(fd, arg);	break;
	case WALNUT_MOUNT:	do_mount(fd, arg);	break;
	case WALNUT_UNMOUNT:	do_unmount(fd, arg);	break;
	case WALNUT_RUNCMD:	do_runcmd(fd, arg);	break;
	default:
		ALOGE("Unknown walnut command: %d\n", arg->cmd);
	}
}

static void *handle_conn(void *arg)
{
	int fd = (int)arg;
	struct walnut_cmd_arg cmd_args;
	char *buf;
	int remain, ret;
	unsigned long rev;

	if (read(fd, &rev, sizeof(rev)) != sizeof(rev)) {
		ALOGE("Error receiving walnut cmd rev nr.: %s\n", strerror(errno));
		goto out;
	}

	if (rev != WALNUT_CMD_REV) {
		ALOGE("Incorrect revision %lx, expected %x\n", rev, WALNUT_CMD_REV);
		goto out;
	}

	buf = (char *)&cmd_args;
	remain = sizeof(cmd_args);
	while (remain > 0) {
		ret = read(fd, buf, remain);
		if (ret < 0) {
			ALOGE("Error receiving cmd args: %s\n", strerror(errno));
			goto out;
		} else if (ret == 0) {
			ALOGE("Unexpected EOF for cmd args\n");
			goto out;
		}

		buf += ret;
		remain -= ret;
	}

	dispatch_walnut_cmd(fd, &cmd_args);
out:
	close(fd);
	return NULL;
}

static int is_running(int pid, const char *name)
{
	int fd;
	int ret;
	char buf[32];
	char fbuf[PATH_MAX];
	int  statpid;
	char pidname[16];
	char pidstate = '\0';

	if (!vdir_exists("/proc/%d", pid))
		return 0;

	snprintf(buf, sizeof(buf), "/proc/%d/stat", pid);
	if (!file_exists(buf))
		return 0;

	fd = open(buf, O_RDONLY);
	if (fd == -1)
		return 0;

	ret = read(fd, fbuf, sizeof(fbuf));
	close(fd);

	if (ret == -1) {
		ALOGE("Could not read %s: %s", buf, strerror(errno));
		return 0;
	}

	memset(pidname, 0, sizeof(pidname));
	sscanf(fbuf, "%d %17s %c", &statpid, pidname, &pidstate);
	ALOGD("RUNING PID %d %s state:%c", statpid, pidname, pidstate);

	/* zombies don't count */
	if (pidstate == 'Z')
		return 0;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	fd = open(buf, O_RDONLY);

	ret = read(fd, fbuf, sizeof(fbuf));
	close(fd);

	if (ret < 0 || !*fbuf)
		return 0;

	if (strcmp(fbuf, name) != 0)
		return 0;

	return 1;
}

/* TODO: set active_walnut based on active_ns_pid */
static int try_reattach(void)
{
	int ret, i;
	struct config_info config;
	struct pty_info console_pty;
	struct walnut_node *new;
	char **name_list;
	name_list = get_walnut_names();
	if (name_list == NULL)
		return -1;

	/* Set console as unavailable */
	console_pty.ptm = -1;

	for (i = 0; name_list[i] != NULL; ++i) {
		if (read_config(name_list[i], &config) == -1)
			continue;
		if (config.initpid == -1)
			continue;

		ALOGI("Trying to re-attach to walnut '%s' (init=%d)",
		     name_list[i], config.initpid);
		ret = is_running(config.initpid, "/init");
		if (!ret) {
			/* Fix the config to indicate walnut has stopped */
			config.initpid = -1;
			write_config(name_list[i], &config);
			ALOGI("walnut '%s' doesn't appear to be running",
			      name_list[i]);
			continue;
		} else if (ret == -1) {
			free_walnut_names(name_list);
			return -1;
		}

		new = create_walnut_node(name_list[i], &config, &console_pty);
		if (new == NULL) {
			free_walnut_names(name_list);
			return -1;
		}
		add_walnut_node(new);
		new->starting = 0;
		new->non_child = 1;
		ALOGI("Re-attached to walnut '%s' (init_pid = %d)",
		     name_list[i], config.initpid);
	}
	free_walnut_names(name_list);
	return 0;
}

static struct walnut_node *walnutd_auto_start_walnut(char *name)
{
	int fd;
	struct walnut_node *ret;
	struct walnut_start_args args;

	fd = open("/dev/null", O_WRONLY);
	if (fd == -1) {
		ALOGE("Could not open /dev/null");
		return NULL;
	}

	args.noopt = 1;
	pthread_mutex_lock(&config_lock);
	ret = __do_start(fd, name, &args);
	pthread_mutex_unlock(&config_lock);
	close(fd);
	return ret;
}

struct autostart_walnut_info {
	char *name;
	int   attempts;
};

static struct autostart_walnut_info *
alloc_autostart_walnut_info(int namelen)
{
	struct autostart_walnut_info *aci;

	aci = malloc(sizeof(*aci) + namelen);
	if (!aci)
		return NULL;

	aci->name = (char *)aci + sizeof(*aci);
	aci->attempts = 0;
	return aci;
}

static void free_autostart_walnut_info(struct autostart_walnut_info *aci)
{
	free(aci);
}

/* Search autostarted array */
static struct autostart_walnut_info *search_autostarted(char *name)
{
	int i;
	for (i = 0; i < arraySize(autostarted_array); ++i) {
		struct autostart_walnut_info *aci = arrayGet(autostarted_array, i);
		if (!aci)
			continue;
		char *cur = aci->name;
		if (strcmp(cur, name) == 0)
			return aci;
	}
	return NULL;
}

static int __autostart_walnuts(void)
{
	int i, idx;
	struct config_info config;
	struct walnut_node *walnut;
	char **name_list;
	struct autostart_walnut_info *aci;

	name_list = get_walnut_names();
	if (name_list == NULL)
		return -1;

	for (i = 0; name_list[i] != NULL; ++i) {
		if (read_config(name_list[i], &config) == -1)
			continue;
		if (config.autostart == 0)
			continue;
		/* Don't start walnuts that were re-attached already */
		if (search_walnuts(name_list[i]) != NULL)
			continue;
		/* Don't start walnuts we've already started */
		aci = search_autostarted(name_list[i]);
		if (aci && aci->attempts >= MAX_WALNUT_AUTOSTART_ATTEMPTS)
			continue;
		/* Add walnut to list of already autostarted walnuts */
		if (!aci) {
			aci = alloc_autostart_walnut_info(strlen(name_list[i]+1));
			if (aci == NULL) {
				ALOGE("No memory for walnut autostart info!");
				continue;
			}
			strcpy(aci->name, name_list[i]);
			idx = arrayAdd(autostarted_array, (void *)aci);
			if (idx == -1) {
				free_autostart_walnut_info(aci);
				continue;
			}
		}

		/* Start walnut */
		ALOGI("Auto starting %s", name_list[i]);
		pthread_mutex_lock(&g_walnut_list.mutex);
		aci->attempts += 1;
		walnut = walnutd_auto_start_walnut(name_list[i]);
		if (walnut == NULL) {
			ALOGE("failed to start %s (attempt=%d)",
			     name_list[i], aci->attempts);
			pthread_mutex_unlock(&g_walnut_list.mutex);
			continue;
		}
		pthread_mutex_unlock(&g_walnut_list.mutex);
	}
	free_walnut_names(name_list);
	return 0;
}

static void *autostart_runner(void* arg)
{
	while (1) {
		__autostart_walnuts();
		sleep(10);
	}
	return (void *)NULL;
}

static void autostart_walnuts(void)
{
	pthread_t tid;
	autostarted_array = arrayCreate();
	pthread_create(&tid, NULL, autostart_runner, (void *)NULL);
}

static void dump_timestamp(char *out)
{
	struct timeval tv;
	char tm_buf[128];
	tm_buf[0] = 0; /* just in case... */
	gettimeofday(&tv, NULL);
	ctime_r(&tv.tv_sec, tm_buf);

	FILE *f_out = fopen(out, "a");
	if (!f_out) {
		ALOGE("Could not open file to dump to (%s)", out);
		return;
	}
	fprintf(f_out, "TIMESTAMP: %s", tm_buf);
	fclose(f_out);
}

/* Dumps one line of numeric characters */
static void dump_file(char *in, char *out)
{
	char *msg;
	int i;
	int ret;
	FILE *fd_out = fopen(out, "a");
	if (fd_out == NULL) {
		ALOGE("Could not open file to dump to (%s)", out);
		return;
	}

	int fd_in = open(in, O_RDONLY);
	if (fd_in == -1) {
		ALOGE("Could not open file to read from (%s)", in);
		msg = "Failed to open input file\n";
	}

	char buf[1024];
	while ((ret = read(fd_in, buf, 1024)) > 0) {
		buf[ret] = '\0';
		fprintf(fd_out, "%s", buf);
	}
	fflush(fd_out);
	close(fd_in);
	fclose(fd_out);
}

static void *power_runner(void* arg)
{
	char *out = "/data/power_info";
	while (1) {
		dump_timestamp(out);
		dump_file("/sys/class/power_supply/battery/uevent", out);
		sleep(10);
	}
	return (void *)0;
}

static void power_info_thread(void)
{
	pthread_t tid;
	pthread_create(&tid, NULL, power_runner, (void *)NULL);
}

static void power_info_only(void)
{
	power_runner((void *)0);
}

static void log_start(void)
{
	struct timeval tv;
	char tm_buf[128];
	tm_buf[0] = 0; /* just in case... */
	gettimeofday(&tv, NULL);
	ctime_r(&tv.tv_sec, tm_buf);
	ALOGI("--- walnutd started on %s", tm_buf);
}

static void walnut_cleanup_and_free(struct walnut_node *walnut, const char *root_path,
				  struct walnut_list *list)
{
	struct config_info config;

	cleanup_walnut_console(&walnut->console_pty);
	if (unmount_all(root_path, 1) == -1)
		ALOGW("Couldn't unmount_all() on %s", root_path);

	/* Try our best to update the config file. Not fatal if we fail. */
	if (read_config(walnut->name, &config) == 0) {
		config.initpid = -1;
		write_config(walnut->name, &config);
	}

	__del_walnut_from(walnut, list);
	free(walnut);
}

static void *walnut_exit_handler(void *unused)
{
	int pid;
	int status, exit_status, exit_signal;
	struct walnut_node *walnut;
	struct walnut_list *list;
	char *root_path;
	struct config_info config;

	ALOGI("Handling SIGCHLD");
	pthread_mutex_lock(&sigchld_lock);
	while (1) {
		pid = waitpid(-1, &status, WNOHANG); /* -1 == WAIT_ANY */

		if (pid == 0 || pid < 0) {

			ALOGE("%s: waitpid out pid: %d, %s", __func__,
			     pid, strerror(errno));
			break;
		}
		exit_status = WEXITSTATUS(status);
		exit_signal = WTERMSIG(status);

		ALOGE("%d exit %s (sig=%d)",
		     pid, (exit_status ? "ERROR" : "SUCCESS"), exit_signal);
		list = &g_dead_walnut_list;
		walnut = search_walnuts_pid(pid, list);
		if (!walnut) {
			ALOGE("pid %d not in deleted walnut list...", pid);
			list = &g_walnut_list;
			walnut = search_walnuts_pid(pid, list);
			if (!walnut) {
				ALOGE("Couldn't find walnut for pid %d", pid);
				break;
			}
		}

                ALOGE("enter god 3!");
		ALOGE("Cell %s terminated by sig %d (%s)", walnut->name, status,
		     (exit_status ? "ERROR" : "SUCCESS"));

		root_path = get_root_path(walnut->name);
		if (!root_path) {
			ALOGE("%s out of memory for walnut rootdir", __func__);
			break;
		}

		if (list != &g_dead_walnut_list) {
			/* do extra cleanup when a walnut just dies... */
			/*
			if (walnut->RIL_PROXY) {
				CLEAN UP RIL PROXY SOCKET
			}
			 */
		}

		/* do the final cleanup and free the walnut_node struct */
		walnut_cleanup_and_free(walnut, root_path, list);
		free(root_path);
		break;
	}

	pthread_mutex_unlock(&sigchld_lock);

	return NULL;
}

/* We need this extra level of indirection because walnut_exit_handler grabs
 * locks that we are not supposed to grab in a signal handler */
static void sigchld_handler(int sig)
{
	pthread_t tid;
	pthread_create(&tid, NULL, walnut_exit_handler, NULL);
}

static void walnutd_main(void)
{
	/* TODO: Create a privileged socket for registering/unregistering.
	 * Create 2 threads here. one for priv, one for regular socket listen */
	int sd, fd, ret;
	struct sockaddr_un addr;
	socklen_t addr_len;
	pthread_t tid;

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1) {
		ALOGE("socket() failed: %s", strerror(errno));
		return;
	}

	fcntl(sd, F_SETFD, FD_CLOEXEC);

	addr_len = init_addr(&addr);

	int ov = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &ov, sizeof(ov)) == -1) {
		ALOGE("Failed to set socket options: %s", strerror(errno));
		goto err;
	}

	if (bind(sd, (struct sockaddr *)&addr, addr_len) == -1) {
		ALOGE("Failed to bind to SOCKET_PATH: %s", strerror(errno));
		goto err;
	}

	if (listen(sd, 10) == -1) {
		ALOGE("listen() failed: %s", strerror(errno));
		goto err;
	}

	while ((fd = accept(sd, (struct sockaddr *)&addr, &addr_len)) != -1) {
		pthread_create(&tid, NULL, handle_conn, (void *)fd);
	}

	ALOGE("cannot accept more incoming connections on socket? %s", strerror(errno));
err:
	close(sd);
	return;
}

static int init_walnutd(const char *procname)
{
	struct stat st;
	int fd = -1, lockpid = -1;
	char lockval[64];

	/* ignore errors */
	mkdir(g_walnut_dir, 0750);

	/* look for the walnutd lockfile */
	if (stat(WALNUTD_LOCKFILE, &st) < 0)
		goto get_lock;

	if (!S_ISREG(st.st_mode)) { /* eh? this would be weird... */
		unlink(WALNUTD_LOCKFILE);
		goto get_lock;
	}

check_lock:
	fd = open(WALNUTD_LOCKFILE, O_RDONLY);
	if (fd < 0) {
		if (errno == EEXIST) {
			unlink(WALNUTD_LOCKFILE);
			goto get_lock;
		}
		goto out_err;
	}

	if (read(fd, lockval, sizeof(lockval)) < 0)
		goto out_err;

	lockpid = atoi(lockval);
	/*
	* If some other process claims to hold the lock, check if that
	* process is in fact around, if not, just grab the lock.  If our pid
	* is in here it means walnutd has been restarted with the same pid,
	* which means that either there was a pid rollover (unlikely) or we
	* rebooted and started with the same pid.  In either case, nobody
	* else can be running walnutd and we are free to grab the lock.
	*/
	if (lockpid != getpid()) {
		if (is_running(lockpid, procname))
			goto out_err;
		/* stale lock */
		ALOGI("removing stale walnutd lockfile");
		unlink(WALNUTD_LOCKFILE);
		goto get_lock;
	}

	/* we have the lock */
	close(fd);
	return 0;

get_lock:
	fd = open(WALNUTD_LOCKFILE, O_RDWR | O_TRUNC | O_CREAT, 0600);
	if (fd < 0)
		goto out_err;

	/*
	 * write our pid into the file, then check to
	 * make sure we didn't race with another instance
	 */
	snprintf(lockval, sizeof(lockval), "%d", getpid());
	if (write(fd, lockval, strlen(lockval)+1) < 0)
		goto out_err;
	close(fd);

	goto check_lock;

out_err:
	if (fd >= 0)
		close(fd);
	ALOGE("Could not obtain walnutd lockfile");
	return -1;
}

static void print_usage(const char *name)
{
	static const char *usage = "\
    -a             Automatically start walnuts with autostart enabled\n\
    -c <dir>       Set Cells directory to <dir> \n\
                           (default: "DEFL_WALNUT_DIR")\n\
    -s <dir>       Set walnut SDCARD directory to <dir> \n\
                           (default: "DEFL_SDCARD_ROOT")\n\
    -F             Run in foreground. don't daemonize.\n\
    -M <path>      Load the system module at <path> before continuing.\n\
                           pass multiple -M to load multiple modules.\n\
    -r             walnutd will attempt to \"re-attach\" to previously\n\
                   running walnuts (eg. after walnutd has restarted)\n\
    -p             Collects power info while running. Info saved\n\
                   to /data/power_info. 10 second polling.\n\
    -P             Only collects power_info. The rest of walnutd\n\
                   does not run. Use for stock images\n\
    -h             displays this message\n";

	printf("Usage: %s [options]\n", name);
	printf("%s", usage);
}

int main(int argc, char **argv)
{
	int c;
	int daemon = 1;
	int reattach_walnuts = 0;
	int autostart = 0;
	int ret;
	void *tret;
	struct sigaction sigact;
	pthread_t tid;

	/* reset our umask */
	umask(0000);

	while ((c = getopt(argc, argv, "ac:s:FM:rpPl:R:h")) != -1) {
		switch (c) {
		case 'a':
			autostart = 1;
			break;
		case 'c':
			g_walnut_dir = optarg;
			ALOGI("Set root Cell dir to %s", g_walnut_dir);
			break;
		case 's':
			g_sdcard_root = optarg;
			ALOGI("Set walnut sdcard root dir to %s", g_sdcard_root);
			break;
		case 'F':
			ALOGI("Running in foreground...");
			daemon = 0;
			break;
		case 'M':
			ALOGI("Loading '%s'...", optarg);
			//			if (insert_module(optarg, NULL) == 0)
			//	ALOGI("Module '%s' loaded.", optarg);
			break;
		case 'r':
			reattach_walnuts = 1;
			break;
		case 'p':
			power_info_thread();
			break;
		case 'P':
			power_info_only();
			exit(0);
		case 'h':
			print_usage(argv[0]);
			exit(0);
		case ':':
			ALOGE("Option %c needs a value", optopt);
		default:
			ALOGE("Invalid start options");
			print_usage(argv[0]);
			exit(1);
		}
	}

	if (init_walnutd(argv[0]) < 0) {
		ALOGI("Could not initialize walnutd. Exiting.");
		fprintf(stderr, "Could not initialize walnutd. Exiting.\n");
		exit(1);
	}

	if (daemon)
		daemonize();

	log_start();

	/*
	 * Initialize Radio Interface Layer (RIL)
	 *     (*) possibly load custom library
	 *     (*) setup proxy host
	 *     (*) pass
	 *     (*) custom arguments to rild
	 */

	/* Setup SIGCHLD handler and ignore SIGPIPEs */
	signal(SIGPIPE, SIG_IGN);
	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = sigchld_handler;
	sigact.sa_flags = SA_NOCLDSTOP;
	ret = sigaction(SIGCHLD, &sigact, NULL);
	if (ret < 0) {
		ALOGE("SIGCHLD sigaction failed\n");
		return EXIT_FAILURE;
	}

	if (reattach_walnuts)
		try_reattach();

	if (autostart)
		autostart_walnuts();

	/*
	 * open the main CellD socket and listen for incoming connections
	 */
	walnutd_main();

	/* Only on error do we get here */
	return EXIT_FAILURE;
}
