/*
 * This file is part of ndppd.
 *
 * Copyright (C) 2011-2019  Daniel Adolfsson <daniel@ashen.se>
 *
 * ndppd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ndppd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ndppd.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "addr.h"
#include "conf.h"
#include "iface.h"
#include "ndppd.h"
#include "proxy.h"
#include "rtnl.h"
#include "rule.h"
#include "sio.h"

#ifndef NDPPD_CONFIG_PATH
#    define NDPPD_CONFIG_PATH "../ndppd.conf"
#endif

long nd_current_time;
bool nd_daemonized;

bool nd_opt_daemonize;
char *nd_opt_config_path;
char *nd_opt_pidfile_path;

static bool ndL_check_pidfile()
{
    int fd = open(nd_opt_pidfile_path, O_RDWR);

    if (fd == -1)
    {
        if (errno == ENOENT)
            return true;

        return false;
    }

    bool result = flock(fd, LOCK_EX | LOCK_NB) == 0;
    close(fd);
    return result;
}

static bool ndL_daemonize()
{
    int fd = open(nd_opt_pidfile_path, O_WRONLY | O_CREAT, 0644);

    if (fd == -1)
        return false;

    if (flock(fd, LOCK_EX | LOCK_NB) < 0)
    {
        close(fd);
        return false;
    }

    pid_t pid = fork();

    if (pid < 0)
    {
        // logger::error() << "Failed to fork during daemonize: " << logger::err();
        return false;
    }

    if (pid > 0)
    {
        char buf[21];
        int len = snprintf(buf, sizeof(buf), "%d", pid);

        if (ftruncate(fd, 0) == -1)
            nd_log_error("Failed to write PID file: ftruncate(): %s", strerror(errno));
        else if (write(fd, buf, len) != 0)
            nd_log_error("Failed to write PID file: write(): %s", strerror(errno));

        nd_iface_no_restore_flags = true;
        exit(0);
    }

    umask(0);

    pid_t sid = setsid();
    if (sid < 0)
    {
        // logger::error() << "Failed to setsid during daemonize: " << logger::err();
        return false;
    }

    if (chdir("/") < 0)
    {
        // logger::error() << "Failed to change path during daemonize: " << logger::err();
        return false;
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    return true;
}

static void ndL_exit()
{
    nd_iface_cleanup();
    nd_rtnl_cleanup();
    nd_alloc_cleanup();
}

static void ndL_sig_exit(__attribute__((unused)) int sig)
{
    exit(0);
}

int main(int argc, char *argv[])
{
    atexit(ndL_exit);
    signal(SIGINT, ndL_sig_exit);
    signal(SIGTERM, ndL_sig_exit);

    static struct option long_options[] = {
        { "config", 1, 0, 'c' }, { "daemon", 0, 0, 'd' },  { "verbose", 0, 0, 'v' },
        { "syslog", 0, 0, 1 },   { "pidfile", 1, 0, 'p' }, { NULL, 0, 0, 0 },
    };

    for (int ch; (ch = getopt_long(argc, argv, "c:dp:v", long_options, NULL)) != -1;)
    {
        switch (ch)
        {
        case 'c':
            nd_opt_config_path = nd_strdup(optarg);
            break;

        case 'd':
            nd_opt_daemonize = true;
            break;

        case 'v':
            if (nd_opt_verbosity < ND_LOG_ERROR)
                nd_opt_verbosity++;
            break;

        case 'p':
            nd_opt_pidfile_path = nd_strdup(optarg);
            break;

        case 1:
            nd_opt_syslog = true;
            break;

        default:
            break;
        }
    }

    struct timeval t1;
    gettimeofday(&t1, 0);
    nd_current_time = t1.tv_sec * 1000 + t1.tv_usec / 1000;

    nd_log_info("ndppd " NDPPD_VERSION);

    if (nd_opt_pidfile_path && !ndL_check_pidfile())
    {
        nd_log_error("Failed to lock pidfile. Is ndppd already running?");
        return -1;
    }

    if (nd_opt_config_path == NULL)
        nd_opt_config_path = NDPPD_CONFIG_PATH;

    nd_log_info("Loading configuration \"%s\"...", nd_opt_config_path);

    if (!nd_conf_load(nd_opt_config_path))
    {
        nd_log_error("Failed to load configuration");
        return -1;
    }

    if (!nd_proxy_startup())
        return -1;

    if (!nd_rtnl_open())
        return -1;

    if (nd_opt_daemonize && !ndL_daemonize())
        return -1;

    nd_rtnl_query_routes();

    bool query_addresses = false;

    while (1)
    {
        if (nd_current_time >= nd_rtnl_dump_timeout)
            nd_rtnl_dump_timeout = 0;

        if (!query_addresses && !nd_rtnl_dump_timeout)
        {
            query_addresses = true;
            nd_rtnl_query_addresses();
        }

        if (!nd_sio_poll())
        {
            /* TODO: Error */
            break;
        }

        nd_proxy_update_all();

        gettimeofday(&t1, 0);
        nd_current_time = t1.tv_sec * 1000 + t1.tv_usec / 1000;
    }

    return 0;
}