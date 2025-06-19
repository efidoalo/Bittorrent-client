/*===============================;
 *
 * File: peer_interactions.h
 * Content: The main header declaring functions and structs
 * whose definitions are used to interact with peers
 * , initially to obtain the info dictionary (through BEP9 https://www.bittorrent.org/beps/bep_0009.html) and then later to transfer the file(s)
 * Date: 19/6/2025
 *
 **********************************/

struct info_dict;
struct connection_ci_state; // for any clinet-peer connection this struct
			    // holds the chocked and interested bit statea			    // of both the client and peer#
struct data_transfer_rate; // struct containing two integers. one for the 
	  // current data transfer rate average, one for the 
	  // present data transfer amount (in bytes) of the current 20 second 
	  // interval. 
          // These two integers are used in a rolling average every
          // 20 seconds to deduce average data transfer rates to base 
          // unchoking peers from (via average download and upload rates)
// TODO: Pipelining - whether to implement in a thread_data structure
// or in peer_interactions thread
struct peer_interactions_thread_independent_data
{
	uint64_t piece_index; // defines the current piece_index (0 starting)
			      // that the program is downloading
	pthread_mutex_t *piece_index_mutex; // mutex for accessing piece_index
	uint8_t *piece_buffer; // pointer to a buffer that stores the 
			       // current piece
	pthread_mutex_t *piece_buffer_mutex; // mutex for accessing piece_buffer
	struct *info_dict; // pointer to the info dictionary, initially NULL
	pthread_mutex_t *info_dict_mutex; //
	struct data_transfer_rate *down_rates; // array of download_rate structures
	pthread_mutex_t *down_rates_mutex;
	struct data_trasnsfer_rate *up_rates;
	pthread_mutex_t *up_rates_mutex;
	struct vector *subpieces_downloaded; // vector of 0 starting integer 
					     // indices
					     // of the subpieces already
					     // downloaded and written to 
					     // piece_buffer
	pthread_mutex_t *subpieces_downloaded_mutex;
};

struct peer_interactions_thread_data
{
	struct peer_interaction_thread_independent_data *thread_independent_data;
	struct vector *peers; // vector giving the peers (address data) 
			      // that this thread manages
	struct connection_ci_states *conn_state; // stores choked/interested 
						 // connection state for 
			// both peer and client for each connection. This is an
			// array
};

