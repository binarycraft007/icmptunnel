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

#include "config.h"
#include "options.h"
#include "client.h"
#include "peer.h"
#include "resolve.h"
#include "protocol.h"
#include "echo-skt.h"
#include "tun-device.h"
#include "handlers.h"
#include "forwarder.h"
#include "client-handlers.h"

static void handle_icmp_packet(struct peer *server)
{
    struct echo_skt *skt = &server->skt;
    struct echo echo;

    /* receive the packet. */
    if (receive_echo(skt, &echo) != 0)
        return;

    /* we're only expecting packets from the server. */
    if (echo.sourceip != server->linkip)
        return;

    /* check the header magic. */
    const struct packet_header *header = &skt->buf->pkth;

    if (memcmp(header->magic, PACKET_MAGIC_SERVER, sizeof(header->magic)) != 0)
        return;

    switch (header->type) {
    case PACKET_DATA:
        /* handle a data packet. */
        handle_client_data(server, &echo);
        break;

    case PACKET_KEEP_ALIVE:
        /* handle a keep-alive packet. */
        handle_keep_alive_response(server);
        break;

    case PACKET_CONNECTION_ACCEPT:
        /* handle a connection accept packet. */
        handle_connection_accept(server);
        break;

    case PACKET_SERVER_FULL:
        /* handle a server full packet. */
        handle_server_full(server);
        break;
    }
}

static void handle_tunnel_data(struct peer *server)
{
    struct echo_skt *skt = &server->skt;
    struct tun_device *device = &server->device;
    int framesize;

    /* read the frame. */
    if (read_tun_device(device, skt->buf->payload, &framesize) != 0)
        return;

    /* if we're not connected then drop the frame. */
    if (!server->connected)
        return;

    /* do not send empty data packets if any. */
    if (!framesize)
        return;

    /* write a data packet. */
    struct packet_header *header = &skt->buf->pkth;
    memcpy(header->magic, PACKET_MAGIC_CLIENT, sizeof(header->magic));
    header->reserved = 0;
    header->type = PACKET_DATA;

    /* send the encapsulated frame to the server. */
    struct echo echo;
    echo.size = framesize;
    echo.id = server->nextid;
    echo.seq = opts.emulation ? server->nextseq : server->nextseq++;
    echo.targetip = server->linkip;

    send_echo(skt, &echo);
}

static void handle_timeout(struct peer *server)
{
    /* send a punch-thru packet. */
    send_punchthru(server);

    /* has the peer timeout elapsed? */
    if (++server->seconds == opts.keepalive) {
        server->seconds = 0;

        /* have we reached the max number of retries? */
        if (opts.retries != -1 && ++server->timeouts == opts.retries) {
            fprintf(stderr, "connection timed out.\n");

            /* stop the packet forwarding loop. */
            stop();
            return;
        }

        /* if we're still connecting, resend the connection request. */
        if (!server->connected) {
            send_connection_request(server);
            return;
        }

        /* otherwise, send a keep-alive request. */
        send_keep_alive(server);
    }
}

static const struct handlers handlers = {
    handle_icmp_packet,
    handle_tunnel_data,
    handle_timeout,
};

int client(const char *hostname)
{
    struct peer server;
    struct echo_skt *skt = &server.skt;
    struct tun_device *device = &server.device;
    int ret = 1;

    /* resolve the server hostname. */
    if (resolve(hostname, &server.linkip) != 0)
        goto err_out;

    /* open an echo socket. */
    if (open_echo_skt(skt, opts.mtu, opts.ttl, 1) != 0)
        goto err_out;

    /* open a tunnel interface. */
    if (open_tun_device(device, opts.mtu) != 0)
        goto err_close_skt;

    /* choose initial icmp id and sequence numbers. */
    server.nextid = rand();
    server.nextseq = rand();

    /* mark as not connected to server. */
    server.connected = 0;

    /* initialize keepalive seconds and timeout retries. */
    server.seconds = 0;
    server.timeouts = 0;

    /* send the initial connection request. */
    send_connection_request(&server);

    /* run the packet forwarding loop. */
    ret = forward(&server, &handlers);

    close_tun_device(device);
err_close_skt:
    close_echo_skt(skt);
err_out:
    return ret;
}
