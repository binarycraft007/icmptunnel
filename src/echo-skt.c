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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "checksum.h"
#include "echo-skt.h"

int open_echo_skt(struct echo_skt *skt, int mtu, int ttl)
{
    skt->buf = NULL;

    /* open the icmp socket. */
    if ((skt->fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        fprintf(stderr, "unable to open icmp socket: %s\n", strerror(errno));
        return 1;
    }

    /* enable/disable ttl security mechanism. */
    if ((skt->ttl = 255 - ttl)) {
        ttl = 255;

        if (setsockopt(skt->fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            fprintf(stderr, "unable to enable ttl security mechanism\n");
            return 1;
        }
    }

    /* calculate the buffer size required to encapsulate this payload. */
    skt->bufsize = mtu + sizeof(struct echo_buf);

    /* allocate the buffer. */
    if ((skt->buf = malloc(skt->bufsize)) == NULL) {
        fprintf(stderr, "unable to allocate icmp tx/rx buffers: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}

int send_echo(struct echo_skt *skt, struct echo *echo)
{
    ssize_t xfer;

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = htonl(echo->targetip);
    dest.sin_port = 0;  /* for valgrind. */

    xfer = sizeof(struct icmphdr) + sizeof(struct packet_header) +  echo->size;

    /* write the icmp header. */
    struct icmphdr *header = &skt->buf->icmph;
    header->type = echo->reply ? ICMP_ECHOREPLY : ICMP_ECHO;
    header->code = 0;
    header->un.echo.id = htons(echo->id);
    header->un.echo.sequence = htons(echo->seq);
    header->checksum = 0;
    header->checksum = checksum(header, xfer);

    /* send the packet. */
    xfer = sendto(skt->fd, header, xfer, 0,
                  (struct sockaddr *)&dest, sizeof(struct sockaddr_in));
    if (xfer < 0) {
        fprintf(stderr, "unable to send icmp packet: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}

int receive_echo(struct echo_skt *skt, struct echo *echo)
{
    ssize_t xfer;

    struct sockaddr_in source;
    socklen_t source_size = sizeof(struct sockaddr_in);

    /* receive a packet. */
    xfer = recvfrom(skt->fd, skt->buf, skt->bufsize, 0,
                    (struct sockaddr *)&source, &source_size);
    if (xfer < 0) {
        fprintf(stderr, "unable to receive icmp packet: %s\n", strerror(errno));
        return 1;
    }

    if (xfer < (int)sizeof(struct echo_buf))
        return 1;  /* bad packet size. */

    if (skt->buf->iph.ttl < skt->ttl)
        return 1;  /* far away than number of hops specified. */

    /* parse the icmp header. */
    const struct icmphdr *header = &skt->buf->icmph;

    switch (header->type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        if (header->code != 0)
            return 1; /* unexpected packet code */
        break;
    default:
        return 1; /* unexpected packet type. */
    }

    echo->size = xfer - sizeof(struct echo_buf);
    echo->reply = header->type == ICMP_ECHOREPLY;
    echo->id = ntohs(header->un.echo.id);
    echo->seq = ntohs(header->un.echo.sequence);
    echo->sourceip = ntohl(source.sin_addr.s_addr);

    return 0;
}

void close_echo_skt(struct echo_skt *skt)
{
    /* dispose of the buffer. */
    if (skt->buf)
        free(skt->buf);

    /* close the icmp socket. */
    if (skt->fd >= 0)
        close(skt->fd);
}
