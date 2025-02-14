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
 *  OUT OF OR IN PEER WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

#ifndef ICMPTUNNEL_PEER_H
#define ICMPTUNNEL_PEER_H

#include <stdint.h>
#include "config.h"
#include "echo-skt.h"
#include "tun-device.h"

struct peer
{
    struct echo_skt skt;
    struct tun_device device;

    /* link address. */
    uint32_t linkip;

    /* next icmp id. */
    uint16_t nextid;

    union {
        struct {
            uint16_t connected;
#define connected u1.c.connected
        } c;
        struct {
            uint16_t strict_nextid;
#define strict_nextid u1.s.strict_nextid
        } s;
    } u1;

    union {
        struct {
            /* client or server in emulation mode sequence numbers. */
            uint16_t nextseq;
#define nextseq u2.c.nextseq
        } c;
        struct {
            /* punch-thru sequence numbers. */
            uint16_t punchthru[ICMPTUNNEL_PUNCHTHRU_WINDOW];
            uint16_t punchthru_idx;
            uint16_t punchthru_write_idx;
#define punchthru_idx u2.s.punchthru_idx
#define punchthru_write_idx u2.s.punchthru_write_idx
#define punchthru u2.s.punchthru
        } s;
    } u2;

    /* number of timeout intervals since last activity. */
    unsigned int seconds;
    unsigned int timeouts;
};

#endif
