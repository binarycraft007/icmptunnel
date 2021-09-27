/*
 *  https://github.com/jamesbarlow/icmptunnel
 *
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2016 James Barlow-Bignell
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

#include <netinet/if_ether.h>

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "client.h"
#include "server.h"
#include "options.h"
#include "forwarder.h"
#include "echo-skt.h"

/* default tunnel mtu in bytes; assume the size of an ethernet frame
 * minus ip, icmp and packet header sizes.
 */
#define ICMPTUNNEL_MTU (1500 - (int)sizeof(struct echo_buf))

#ifndef ETH_MIN_MTU
#define ETH_MIN_MTU 68
#endif
#ifndef ETH_MAX_MTU
#define ETH_MAX_MTU 0xFFFFU
#endif

static void version()
{
    fprintf(stderr, "icmptunnel is version %s (built %s).\n", ICMPTUNNEL_VERSION, __DATE__);
    exit(0);
}

static void help(const char *program)
{
    fprintf(stderr, "icmptunnel %s.\n", ICMPTUNNEL_VERSION);
    fprintf(stderr, "usage: %s [options] -s|server\n\n", program);
    fprintf(stderr, "  -v               print version and exit.\n");
    fprintf(stderr, "  -h               print help and exit.\n");
    fprintf(stderr, "  -k <interval>    interval between keep-alive packets.\n");
    fprintf(stderr, "                   the default interval is %i seconds.\n", ICMPTUNNEL_TIMEOUT);
    fprintf(stderr, "  -r <retries>     packet retry limit before timing out.\n");
    fprintf(stderr, "                   the default is %i retries.\n", ICMPTUNNEL_RETRIES);
    fprintf(stderr, "  -m <mtu>         max frame size of the tunnel interface.\n");
    fprintf(stderr, "                   the default tunnel mtu is %i bytes.\n", ICMPTUNNEL_MTU);
    fprintf(stderr, "  -e               emulate the microsoft ping utility.\n");
    fprintf(stderr, "  -d               run in the background as a daemon.\n");
    fprintf(stderr, "  -s               run in server-mode.\n");
    fprintf(stderr, "  -t <hops>        use ttl security mode.\n");
    fprintf(stderr, "                   the default is to not use this mode.\n");
    fprintf(stderr, "  -i <id>          set instance id used in ICMP request/reply id field.\n");
    fprintf(stderr, "                   the default is to use generated on startup.\n");
    fprintf(stderr, "  server           run in client-mode, using the server ip/hostname.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Note that process requires CAP_NET_RAW to open ICMP raw sockets\n");
    fprintf(stderr, "and CAP_NET_ADMIN to manage tun devices. You should run either\n");
    fprintf(stderr, "as root or grant above capabilities (e.g. via POSIX file capabilities)\n");
    fprintf(stderr, "\n");

    exit(0);
}

static void usage(const char *program)
{
    fprintf(stderr, "unknown or missing option -- '%c'\n", optopt);
    fprintf(stderr, "use %s -h for more information.\n", program);
    exit(1);
}

static void signalhandler(int sig)
{
    /* unused variable. */
    (void)sig;

    stop();
}

struct options opts = {
    ICMPTUNNEL_TIMEOUT,
    ICMPTUNNEL_RETRIES,
    ICMPTUNNEL_MTU,
    ICMPTUNNEL_EMULATION,
    ICMPTUNNEL_DAEMON,
    255,
    UINT16_MAX + 1,
};

int main(int argc, char *argv[])
{
    char *program = argv[0];
    char *hostname = NULL;
    int servermode = 0;

    /* parse the option arguments. */
    opterr = 0;
    int opt;
    while ((opt = getopt(argc, argv, "vhk:r:m:edst:i:")) != -1) {
        switch (opt) {
        case 'v':
            version();
            break;
        case 'h':
            help(program);
            break;
        case 'k':
            opts.keepalive = atoi(optarg);
            if (!opts.keepalive)
                opts.keepalive = 1;
            break;
        case 'r':
            if (!strcmp(optarg, "infinite"))
                opts.retries = -1;
            else
                opts.retries = atoi(optarg);
            break;
        case 'm':
            opts.mtu = atoi(optarg);
            if (opts.mtu < ETH_MIN_MTU || opts.mtu > ETH_MAX_MTU) {
                fprintf(stderr, "for -m option mtu must be within %u ... %u range\n",
                        ETH_MIN_MTU, ETH_MAX_MTU);
                exit(1);
            }
            break;
        case 'e':
            opts.emulation = 1;
            break;
        case 'd':
            opts.daemon = 1;
            break;
        case 's':
            servermode = 1;
            break;
        case 't':
            opts.ttl = atoi(optarg);
            if (opts.ttl > 254) {
                fprintf(stderr, "for -t option hops must be within 0 ... 254\n");
                exit(1);
            }
            break;
        case 'i':
            opts.id = atoi(optarg);
            if (opts.id > UINT16_MAX) {
                fprintf(stderr, "for -i option id must be within 0 ... 65535\n");
                exit(1);
            }
            break;
        case '?':
            /* fall-through. */
        default:
            usage(program);
            break;
        }
    }

    argc -= optind;
    argv += optind;

    /* if we're running in client mode, parse the server hostname. */
    if (!servermode) {
        if (argc < 1) {
            fprintf(stderr, "missing server ip/hostname.\n");
            fprintf(stderr, "use %s -h for more information.\n", program);
            return 1;
        }
        hostname = argv[0];

        argc--;
        argv++;
    }

    /* check for extraneous options. */
    if (argc > 0) {
        fprintf(stderr, "unknown option -- '%s'\n", argv[0]);
        fprintf(stderr, "use %s -h for more information.\n", program);
        return 1;
    }

    /* register the signal handlers. */
    signal(SIGINT, signalhandler);
    signal(SIGTERM, signalhandler);

    srand(getpid() + (time(NULL) % getppid()));

    if (servermode) {
        /* run the server. */
        return server();
    } else {
        /* run the client. */
        return client(hostname);
    }
}
