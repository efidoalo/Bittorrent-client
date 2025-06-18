/*=============================;
 *
 * File: peers.h
 * Content: Header file declaring functions
 * and structs required for getting peer
 * list from trackers.
 * Date: 12/6/2025
 *
 *************************************/

#ifndef __PEERS_H_INCLUDED__
#define __PEERS_H_INCLUDED__

#include "binary_tree.h"
#include "vector.h"
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <time.h>
#include <poll.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>

// struct for holding peer date
// ip port and possibly peer id
struct peer;

// struct that each thread uses when requesting peer
// lists from trackers. The thread uses this struct to
// append any peer lists that it has to the struct.
struct peer_discovery_thread_independent_data;

// routine that is run as numerous threads to obtain
// peer list from trackers
void *peer_discovery(void *thread_data);

// function for seeding random number generator for calls to rand()
void start_rand();

// generate 20 byte peer_id for clinet use
uint8_t *generate_peer_id();

// fills the peer_discovery_thread_independent_data structures
void fill_peer_discovery_thread_structures(struct peer_discovery_thread_independent_data *pdt,
					   int NoOfTrackers,
			   		   int no_of_peer_discovery_threads,
			                   int max_number_of_threads,
			                   struct vector *tracker_vect,
					   uint8_t *info_hash,
					   uint8_t *peer_id,
					   pthread_mutex_t *access_peers_tree_mutex);			   
#endif
