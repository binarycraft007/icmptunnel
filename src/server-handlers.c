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

#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>

#include "peer.h"
#include "echo-skt.h"
#include "tun-device.h"
#include "protocol.h"
#include "server-handlers.h"

void handle_server_data(struct peer *client, struct echo *request)
{
    struct echo_skt *skt = &client->skt;
    struct tun_device *device = &client->device;
    int framesize = request->size;

    if (!client->connected || request->sourceip != client->linkip)
        return;

    /* determine the size of the encapsulated frame. */
    if (!framesize)
        return;

    /* write the frame to the tunnel interface. */
    write_tun_device(device, skt->buf->payload, framesize);

    /* save the icmp id and sequence numbers for any return traffic. */
    handle_punchthru(client, request);
}

void handle_keep_alive_request(struct peer *client, struct echo *request)
{
    struct echo_skt *skt = &client->skt;

    if (!client->connected || request->sourceip != client->linkip)
        return;

    /* write a keep-alive response. */
    struct packet_header *header = &skt->buf->pkth;
    memcpy(header->magic, PACKET_MAGIC_SERVER, sizeof(header->magic));
    header->reserved = 0;
    header->type = PACKET_KEEP_ALIVE;

    /* send the response to the client. */
    struct echo response;
    response.size = 0;
    response.reply = 1;
    response.id = request->id;
    response.seq = request->seq;
    response.targetip = request->sourceip;

    send_echo(skt, &response);

    client->seconds = 0;
    client->timeouts = 0;
}

void handle_connection_request(struct peer *client, struct echo *request)
{
    struct echo_skt *skt = &client->skt;
    char *verdict, ip[sizeof("255.255.255.255")];
    uint32_t nip;

    struct packet_header *header = &skt->buf->pkth;
    memcpy(header->magic, PACKET_MAGIC_SERVER, sizeof(struct packet_header));
    header->reserved = 0;

    /* is a client already connected? */
    if (client->connected) {
        header->type = PACKET_SERVER_FULL;
        verdict = "ignoring";
    } else {
        header->type = PACKET_CONNECTION_ACCEPT;
        verdict = "accepting";

        client->connected = 1;
        client->seconds = 0;
        client->timeouts = 0;
        client->punchthru_wrap = 0;
        client->punchthru_idx = 0;
        client->punchthru_write_idx = 0;
        client->linkip = request->sourceip;
    }

    nip = htonl(request->sourceip);
    inet_ntop(AF_INET, &nip, ip, sizeof(ip));
    fprintf(stderr, "%s connection from %s\n", verdict, ip);

    /* send the response. */
    struct echo response;
    response.size = 0;
    response.reply = 1;
    response.id = request->id;
    response.seq = request->seq;
    response.targetip = request->sourceip;

    send_echo(skt, &response);
}

/* handle a punch-thru packet. */
void handle_punchthru(struct peer *client, struct echo *request)
{
    if (!client->connected || request->sourceip != client->linkip)
        return;

    /* store the id number. */
    client->nextid = request->id;

    /* store the sequence number. */
    client->punchthru[client->punchthru_write_idx++] = request->seq;

    if (!(client->punchthru_write_idx %= ICMPTUNNEL_PUNCHTHRU_WINDOW))
        client->punchthru_wrap = 1;

    client->seconds = 0;
    client->timeouts = 0;
}
