/*===============================;
 *
 * File: recv.h
 * Content: Header for receive function
 * that receives a BitTorrent packet
 * of data that is length prefixed.
 * Date: 26/6/2025
 *
 **************************************/

#ifndef __RECV_H_INCLUDED__
#define __RECV_H_INCLUDED__

#include <poll.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>

// Thread safe function that receives a BitTorrent packet
// and returns a pointer to it, bytes_read on function return
// stores the total amount of data in the packet.
// client_socket_fd is a socket connected to a peer
// Function returns the null pointer with bytes_read set to zero
// either on error or if a timeout occurs before receipt of full packet
// ms_timeout number of milliseconds to wait for a timeout.
// Mutexes are provided for thread safety. These are the thread_independent_data
// mutexes. Skips keep alives
uint8_t *recv_packet(int client_socket_fd, int *bytes_read, int ms_timeout,
		     pthread_mutex_t *recv_mutex,
		     pthread_mutex_t *poll_mutex,
		     pthread_mutex_t *mem_mutex);

#endif
