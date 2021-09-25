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

#include "peer.h"
#include "echo-skt.h"
#include "tun-device.h"
#include "protocol.h"
#include "server-handlers.h"

void handle_server_data(struct peer *client, int framesize)
{
    struct echo_skt *skt = &client->skt;
    struct tun_device *device = &client->device;

    /* determine the size of the encapsulated frame. */
    if (!framesize)
        return;

    /* write the frame to the tunnel interface. */
    write_tun_device(device, skt->buf->payload, framesize);

    /* save the icmp id and sequence numbers for any return traffic. */
    handle_punchthru(client);
}

void handle_keep_alive_request(struct peer *client)
{
    struct echo_skt *skt = &client->skt;

    /* write a keep-alive response. */
    struct packet_header *pkth = &skt->buf->pkth;
    memcpy(pkth->magic, PACKET_MAGIC_SERVER, sizeof(pkth->magic));
    pkth->reserved = 0;
    pkth->type = PACKET_KEEP_ALIVE;

    /* send the response to the client. */
    send_echo(skt, client->linkip, 0);

    client->seconds = 0;
    client->timeouts = 0;
}

void handle_connection_request(struct peer *client)
{
    struct echo_skt *skt = &client->skt;
    uint32_t sourceip = skt->buf->iph.saddr;
    char *verdict, ip[sizeof("255.255.255.255")];

    struct packet_header *pkth = &skt->buf->pkth;
    memcpy(pkth->magic, PACKET_MAGIC_SERVER, sizeof(pkth->magic));
    pkth->reserved = 0;

    /* is a client already connected? */
    if (client->linkip) {
        pkth->type = PACKET_SERVER_FULL;
        verdict = "ignoring";
    } else {
        pkth->type = PACKET_CONNECTION_ACCEPT;
        verdict = "accepting";

        client->seconds = 0;
        client->timeouts = 0;
        client->punchthru_wrap = 0;
        client->punchthru_idx = 0;
        client->punchthru_write_idx = 0;
        client->linkip = sourceip;
    }

    inet_ntop(AF_INET, &sourceip, ip, sizeof(ip));
    fprintf(stderr, "%s connection from %s\n", verdict, ip);

    /* send the response. */
    send_echo(skt, sourceip, 0);
}

/* handle a punch-thru packet. */
void handle_punchthru(struct peer *client)
{
    struct icmphdr *icmph = &client->skt.buf->icmph;

    /* store the id number. */
    client->nextid = icmph->un.echo.id;

    /* store the sequence number. */
    client->punchthru[client->punchthru_write_idx++] = icmph->un.echo.sequence;

    if (!(client->punchthru_write_idx %= ICMPTUNNEL_PUNCHTHRU_WINDOW))
        client->punchthru_wrap = 1;

    client->seconds = 0;
    client->timeouts = 0;
}
