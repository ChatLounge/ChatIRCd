/*
 * librb-config.h: libratbox config file. Please modify configure.ac
 */

#ifndef __LIBRB_CONFIG_H
#define __LIBRB_CONFIG_H

#define RB_IPV6 1
#define RB_HAVE_ALLOCA_H 1
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <crypt.h>
#include <errno.h>
typedef socklen_t rb_socklen_t;
#define rb_sockaddr_storage sockaddr_storage
#endif /* __LIBRB_CONFIG_H */
