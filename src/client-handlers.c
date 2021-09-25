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

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "peer.h"
#include "daemon.h"
#include "options.h"
#include "echo-skt.h"
#include "tun-device.h"
#include "protocol.h"
#include "forwarder.h"
#include "client-handlers.h"

void handle_client_data(struct peer *server, int framesize)
{
    struct echo_skt *skt = &server->skt;
    struct tun_device *device = &server->device;

    /* if we're not connected then drop the packet. */
    if (!server->connected)
        return;

    /* determine the size of the encapsulated frame. */
    if (!framesize)
        return;

    /* write the frame to the tunnel interface. */
    if (write_tun_device(device, skt->buf->payload, framesize) < 0)
        return;

    server->seconds = 0;
    server->timeouts = 0;

    /* send punch-thru to avoid server sequence number starvartion. */
    if (device->iopkts + 1 >= ICMPTUNNEL_PUNCHTHRU_WINDOW / 2)
        send_punchthru(server);
    else
        device->iopkts++;
}

void handle_keep_alive_response(struct peer *server)
{
    /* if we're not connected then drop the packet. */
    if (!server->connected)
        return;

    server->seconds = 0;
    server->timeouts = 0;
}

void handle_connection_accept(struct peer *server)
{
    char ip[sizeof("255.255.255.255")];

    /* if we're already connected then ignore the packet. */
    if (server->connected)
        return;

    inet_ntop(AF_INET, &server->linkip, ip, sizeof(ip));
    fprintf(stderr, "connection established with %s.\n", ip);

    server->connected = 1;
    server->seconds = 0;
    server->timeouts = 0;

    /* fork and run as a daemon if needed. */
    if (opts.daemon) {
        if (daemon() != 0)
            return;
    }

    /* send the initial punch-thru packets. */
    send_punchthru(server);
}

void handle_server_full(struct peer *server)
{
    /* if we're already connected then ignore the packet. */
    if (server->connected)
        return;

    fprintf(stderr, "unable to connect: server is full.\n");

    /* stop the packet forwarding loop. */
    stop();
}

int send_message(struct peer *server, int pkttype, int size)
{
    struct echo_skt *skt = &server->skt;

    /* write a connection request packet. */
    struct packet_header *pkth = &skt->buf->pkth;
    memcpy(pkth->magic, PACKET_MAGIC_CLIENT, sizeof(pkth->magic));
    pkth->reserved = 0;
    pkth->type = pkttype;

    /* send packet. */
    struct icmphdr *icmph = &skt->buf->icmph;
    icmph->un.echo.id = server->nextid;
    icmph->un.echo.sequence = server->nextseq;

    if (!opts.emulation)
        server->nextseq = htons(ntohs(server->nextseq) + 1);

    return send_echo(skt, server->linkip, size);
}
