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

#include <stdio.h>
#include <string.h>

#include "peer.h"
#include "daemon.h"
#include "options.h"
#include "echo-skt.h"
#include "tun-device.h"
#include "protocol.h"
#include "forwarder.h"
#include "client-handlers.h"

void handle_client_data(struct peer *server, struct echo *echo)
{
    struct echo_skt *skt = &server->skt;
    struct tun_device *device = &server->device;

    /* if we're not connected then drop the packet. */
    if (!server->connected)
        return;

    /* determine the size of the encapsulated frame. */
    int framesize = echo->size - sizeof(struct packet_header);

    if (!framesize)
        return;

    /* write the frame to the tunnel interface. */
    write_tun_device(device, skt->data + sizeof(struct packet_header), framesize);

    server->seconds = 0;
    server->timeouts = 0;
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
    int i;

    /* if we're already connected then ignore the packet. */
    if (server->connected)
        return;

    fprintf(stderr, "connection established.\n");

    server->connected = 1;
    server->seconds = 0;
    server->timeouts = 0;

    /* fork and run as a daemon if needed. */
    if (opts.daemon) {
        if (daemon() != 0)
            return;
    }

    /* send the initial punch-thru packets. */
    for (i = 0; i < ICMPTUNNEL_PUNCHTHRU_WINDOW; i++) {
        send_punchthru(server);
    }
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

void send_message(struct peer *server, int pkttype)
{
    struct echo_skt *skt = &server->skt;

    /* write a connection request packet. */
    struct packet_header *header = (struct packet_header*)skt->data;
    memcpy(header->magic, PACKET_MAGIC, sizeof(header->magic));
    header->type = pkttype;

    /* send the request. */
    struct echo request;
    request.size = sizeof(struct packet_header);
    request.reply = 0;
    request.id = server->nextid;
    request.seq = opts.emulation ? server->nextseq : server->nextseq++;
    request.targetip = server->linkip;

    send_echo(skt, &request);
}
