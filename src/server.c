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
#include "daemon.h"
#include "options.h"
#include "server.h"
#include "peer.h"
#include "protocol.h"
#include "echo-skt.h"
#include "tun-device.h"
#include "handlers.h"
#include "forwarder.h"
#include "server-handlers.h"

static void handle_icmp_packet(struct peer *client)
{
    struct echo_skt *skt = &client->skt;
    struct echo echo;

    /* receive the packet. */
    if (receive_echo(skt, &echo) != 0)
        return;

    /* check the header magic. */
    const struct packet_header *header = &skt->buf->pkth;

    if (memcmp(header->magic, PACKET_MAGIC_CLIENT, sizeof(header->magic)) != 0)
        return;

    switch (header->type) {
    case PACKET_DATA:
        /* handle a data packet. */
        handle_server_data(client, &echo);
        break;

    case PACKET_KEEP_ALIVE:
        /* handle a keep-alive request packet. */
        handle_keep_alive_request(client, &echo);
        break;

    case PACKET_CONNECTION_REQUEST:
        /* handle a connection request packet. */
        handle_connection_request(client, &echo);
        break;

    case PACKET_PUNCHTHRU:
        /* handle a punch-thru packet. */
        handle_punchthru(client, &echo);
        break;
    }
}

static void handle_tunnel_data(struct peer *client)
{
    struct echo_skt *skt = &client->skt;
    struct tun_device *device = &client->device;
    int framesize;

    /* read the frame. */
    if (read_tun_device(device, skt->buf->payload, &framesize) != 0)
        return;

    /* if no client is connected then drop the frame. */
    if (!client->connected)
        return;

    /* if no punchthru entries then drop the frame. */
    if (!client->punchthru_wrap)
        if (client->punchthru_idx == client->punchthru_write_idx)
            return;

    /* write a data packet. */
    struct packet_header *header = &skt->buf->pkth;
    memcpy(header->magic, PACKET_MAGIC_SERVER, sizeof(header->magic));
    header->reserved = 0;
    header->type = PACKET_DATA;

    /* send the encapsulated frame to the client. */
    struct echo echo;
    echo.size = framesize;
    echo.id = client->nextid;
    echo.seq = client->punchthru[client->punchthru_idx++];
    echo.targetip = client->linkip;

    if (!(client->punchthru_idx %= ICMPTUNNEL_PUNCHTHRU_WINDOW))
        client->punchthru_wrap = 0;

    send_echo(skt, &echo);
}

static void handle_timeout(struct peer *client)
{
    if (!client->connected)
        return;

    /* has the peer timeout elapsed? */
    if (++client->seconds == opts.keepalive) {
        client->seconds = 0;

        /* have we reached the max number of retries? */
        if (opts.retries != -1 && ++client->timeouts == opts.retries) {
            fprintf(stderr, "client connection timed out.\n");

            client->connected = 0;
            return;
        }
    }
}

static const struct handlers handlers = {
    handle_icmp_packet,
    handle_tunnel_data,
    handle_timeout,
};

int server(void)
{
    struct peer client;
    struct echo_skt *skt = &client.skt;
    struct tun_device *device = &client.device;
    int ret = 1;

    /* open an echo socket. */
    if (open_echo_skt(skt, opts.mtu, opts.ttl, 0) != 0)
        goto err_out;

    /* open a tunnel interface. */
    if (open_tun_device(device, opts.mtu) != 0)
        goto err_close_skt;

    /* fork and run as a daemon if needed. */
    if (opts.daemon) {
        if (daemon() != 0)
            goto err_close_tun;
    }

    /* mark as not connected with client. */
    client.connected = 0;

    /* initialize keepalive seconds and timeout retries. */
    client.seconds = 0;
    client.timeouts = 0;

    /* run the packet forwarding loop. */
    ret = forward(&client, &handlers);

err_close_tun:
    close_tun_device(device);
err_close_skt:
    close_echo_skt(skt);
err_out:
    return ret;
}
