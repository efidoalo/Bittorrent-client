/*===============================;
 *
 * File: peer_interactions.h
 * Content: The main header declaring functions and structs
 * whose definitions are used to interact with peers
 * , initially to obtain the info dictionary (through BEP9 https://www.bittorrent.org/beps/bep_0009.html) and then later to transfer the file(s)
 * Date: 19/6/2025
 *
 **********************************/

#ifndef __PEER_INTERACTIONS_H_INCLUDED__
#define __PEER_INTERACTIONS_H_INCLUDED__

#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "vector.h"
#include "binary_tree.h"
#include "peers.h"
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

struct files
{
        uint64_t length; // number of bytes this file has
        char *path; // the path in the directory of this file, the last
                    // component of the path is the file name
        struct files *next; // pointer to the next file in the download
                            // if NULL this files is the last file in the
                            // download
};


struct info_dict
{
        char *name; // suggested name of file or directory
        uint32_t piece_length;
        uint8_t *pieces; // sequence of 20 byte sha1 hashes of corresponding
                         // download pieces
        uint64_t length;
        struct files *f;
};

struct connection_ci_state; // for any clinet-peer connection this struct
			    // holds the chocked and interested bit statea			    // of both the client and peer#
struct data_transfer_rate; // struct containing two integers. one for the 
	  // current data transfer rate average, one for the 
	  // present data transfer amount (in bytes) of the current 20 second 
	  // interval. 
          // These two integers are used in a rolling average every
          // 20 seconds to deduce average data transfer rates to base 
          // unchoking peers from (via average download and upload rates)

struct peer_interactions_thread_independent_data
{
	uint64_t NoOfPeers; // this changes from the amount that the tracker returned
			    // to the number of connected peers
	pthread_mutex_t *NoOfPeers_mutex; 
	uint64_t piece_index; // defines the current piece_index (0 starting)
			      // that the program is downloading
	pthread_mutex_t *piece_index_mutex; // mutex for accessing piece_index
	uint8_t *piece_buffer; // pointer to a buffer that stores the 
			       // current piece
	pthread_mutex_t *piece_buffer_mutex; // mutex for accessing piece_buffer
	struct info_dict *info_dict; // pointer to the info dictionary, initially NULL
	pthread_mutex_t *info_dict_mutex; //
	struct vector *subpieces_downloaded; // vector of 0 starting integer 
					     // indices
					     // of the subpieces already
					     // downloaded and written to 
					     // piece_buffer
	pthread_mutex_t *subpieces_downloaded_mutex;
	uint8_t *info_hash;
	pthread_mutex_t *info_hash_mutex;
	uint8_t *peer_id;
	pthread_mutex_t *peer_id_mutex;
};

struct peer_interactions_thread_data
{	
	struct peer_interactions_thread_independent_data *thread_independent_data;
	struct vector *peers; // vector giving the peers (address data) 
			      // that this thread manages
	pthread_mutex_t *peers_vector_mutex; // required for adding new peers

	struct connection_ci_state *conn_state; // stores choked/interested 
						 // connection state for 
			// both peer and client for each connection. This is an
			// array
	pthread_mutex_t *conn_state_mutex; // required for adding new peers, 1 mutex for
					   // each peer
	struct vector **pipelined_peer_requests; // vector whereby each element
						// is a vector of 5 integers
						// defining the pipelined
						// subpiece indices each peer
						// should request next
						// . No access mutex required
	pthread_mutex_t *pipelined_peer_requests_mutex; // required for adding new peers
	struct data_transfer_rate *down_rates; // array of download rates 
        pthread_mutex_t *down_rates_mutex; // 
        struct data_transfer_rate *up_rates; // array of upload rates
        pthread_mutex_t *up_rates_mutex; // 
	uint8_t *handshake_completed; // array 
	pthread_mutex_t *hshake_mutex; // single mutex
};

struct peer_interactions_thread_data *
get_peer_interactions_thread_data_structures(
                int peer_interactions_thread_count,
                int NoOfPeers,
                struct binary_tree *peers_tree,
                int max_number_of_threads,
		uint8_t *info_hash,
		uint8_t *peer_id);

// the function that runs as seperate threads processing peer interactions
void *peer_interactions(void *pd); 

#endif
