/*==============================;
 *
 * File: peer_interactions.c
 * Content: Struct definitions to implement
 * the peer_interactipns_thread_independent_data struct
 * and the peer_interactions_thread_data struct 
 * which are used to connect to peers and down/upload
 * the file(d)
 * Date: 23/6/2025
 *
 ***********************************/

#include "peer_interactions.h"

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

struct connection_ci_state {
	uint8_t client_choke_state; // 0 for client choking th peer
				    // 1 for clinet unchoking the peer
	uint8_t client_interested_state; // 0 for client not interested
					 // 1 for client interested in data 
					 // from peer
	uint8_t peer_choke_state; // 0 for peer choking client
				  // 1 for peer unchoking client
	uint8_t peer_interested_state; // 0 for peer not interested in client 
				       // data
				       // 1 for peer interested in client data
};	

struct data_transfer_rate
{
	uint64_t previous_transfer_rate; // the previous rolling averaged
					 // transfer rate (calculated every 20
					 // seconds)
	uint64_t curr_data_transferred; // number of bytes trasferred during
				       // this current 20 second window	
};

void *peer_interactions(void *d)
{
        struct peer_interactions_thread_data *ptd = (struct peer_interactions_thread_data *)d;
 
}

void print_integer(void *integer)
{
	int *i = (int *)integer;
	printf("%d", *i);
}

void get_peer_interactions_thread_data_structures(
		int peer_interactions_thread_count,
		int NoOfPeers,
		struct binary_tree *peers_tree,
		int max_number_of_threads)
{
		
	struct peer_interactions_thread_data *ptd = (struct peer_interactions_thread_data *)malloc(sizeof(struct peer_interactions_thread_data)*peer_interactions_thread_count);
        if (ptd == NULL) {
                printf("Error allocating memory for peer interactions thread daya. %s\n",
                                strerror(errno));
                exit(EXIT_FAILURE);
        }
		
	struct peer_interactions_thread_independent_data *pitd = (struct peer_interactions_thread_independent_data *)malloc(sizeof(struct peer_interactions_thread_independent_data));
        if (pitd == NULL) {
                printf("Error allocating memory for thread independent peer interactions"
                        " data structure. %s.\n", strerror(errno));
                exit(EXIT_FAILURE);
        }
	pitd->piece_index = 0; // initial default value
	pitd->piece_index_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if ((pitd->piece_index_mutex)==NULL) {
		printf("Error allocating memory for piece index mutex. %s.\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	pthread_mutex_init(pitd->piece_index_mutex, NULL);
	pitd->piece_buffer = NULL; // defalt unallocated buffer
	pitd->piece_buffer_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if ((pitd->piece_buffer_mutex) == NULL) {
		printf("Error allocating memory for the piece buffer mutex.%s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	pthread_mutex_init(pitd->piece_buffer_mutex, NULL);
	pitd->info_dict = NULL;
	pitd->info_dict_mutex = (pthread_mutex_t  *)malloc(sizeof(struct info_dict));
	if ((pitd->info_dict_mutex) == NULL) {
		printf("Error allocating memory for info dict mutex. %s.\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	pthread_mutex_init(pitd->info_dict_mutex, NULL);
	pitd->down_rates = (struct data_transfer_rate *)malloc(sizeof(struct data_transfer_rate)*NoOfPeers);
	if ((pitd->down_rates) == NULL) {
		printf("Error allocating memory to store download rates.%s.\n", 
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	for (int i=0; i<NoOfPeers; ++i) {
		(pitd->down_rates)[i].previous_transfer_rate = 0; 
                (pitd->down_rates)[i].curr_data_transferred = 0;	
	}
	pitd->down_rates_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if ((pitd->down_rates_mutex) == NULL) {
		printf("Error allocating ,memory for download rates mutex.%s.\n",			strerror(errno));
		exit(EXIT_FAILURE);
	}
	pthread_mutex_init(pitd->down_rates_mutex, NULL);
	pitd->up_rates = (struct data_transfer_rate *)malloc(sizeof(struct data_transfer_rate)*NoOfPeers);
	if ((pitd->up_rates) == NULL) {
		printf("Error allocating memory for upload rates.%s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	for (int i=0; i<NoOfPeers; ++i) {
                (pitd->up_rates)[i].previous_transfer_rate = 0;
                (pitd->up_rates)[i].curr_data_transferred = 0;
        }

	pitd->up_rates_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if ((pitd->up_rates_mutex) == NULL) {
		printf("Error allocating memory for upload rates mutex. %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	pthread_mutex_init(pitd->up_rates_mutex, NULL);
	
	pitd->subpieces_downloaded = vector_null_init(sizeof(int), print_integer);
        if ((pitd->subpieces_downloaded)==NULL)	{
		printf("Error allcoating vector to store subpiece indices that have been downloaded.\n");
		exit(EXIT_FAILURE);
	}
	pitd->subpieces_downloaded_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if ((pitd->subpieces_downloaded_mutex) == NULL) {
		printf("Error allocating subpieces_downloaded mutex. %s.\n",
				strerror(errno));
	}
	pthread_mutex_init(pitd->subpieces_downloaded_mutex, NULL);
	int curr_peer_index = 0;
	for (int i=0; i<peer_interactions_thread_count; ++i) {
                int NoOfHandledPeers = NoOfPeers/(max_number_of_threads-1);
                if (i == (peer_interactions_thread_count-1)) {
                	NoOfHandledPeers += NoOfPeers % (max_number_of_threads-1);
                }
                struct vector *peers = vector_null_init(sizeof(struct peer), print_peer);	
		for (int j=0; j<NoOfHandledPeers; ++j) {
			struct peer *p = (struct peer *)btree_get(peers_tree, curr_peer_index + j);
			vector_push_back(peers, p);
		}
		curr_peer_index += NoOfHandledPeers;
		(ptd[i]).thread_independent_data = pitd;
		(ptd[i]).peers = peers;
		(ptd[i]).peers_vector_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
		if (((ptd[i]).peers_vector_mutex) == NULL) {
			printf("Error allocating memory for peers vector mutex. %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		pthread_mutex_init((ptd[i]).peers_vector_mutex, NULL);
		(ptd[i]).conn_state = (struct connection_ci_state *)malloc(sizeof(struct connection_ci_state)*NoOfHandledPeers);
		if ((ptd[i]).conn_state == NULL ) {
			printf("Error allocating memory for connection choke/interested state. %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		for (int j=0; j<NoOfHandledPeers; ++j) {
			(((ptd[i]).conn_state)[j]).client_choke_state = 0;
			(((ptd[i]).conn_state)[j]).client_interested_state = 0;
			(((ptd[i]).conn_state)[j]).peer_choke_state = 0;
			(((ptd[i]).conn_state)[j]).peer_interested_state = 0;
		}
		(ptd[i]).conn_state_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
		if ( (ptd[i]).conn_state_mutex == NULL) {
			printf("Error allocating memory for connection state mutexes, %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		
		pthread_mutex_init((ptd[i]).conn_state_mutex, NULL);
		(ptd[i]).pipelined_peer_requests = (struct vector **)malloc(sizeof(struct vector *)*NoOfHandledPeers);
		if ((ptd[i]).pipelined_peer_requests == NULL) {
			printf("Error allocating memory for pipelined request vector. %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		for (int j=0; j<NoOfHandledPeers; ++j) {
			((ptd[i]).pipelined_peer_requests)[j] = vector_null_init(sizeof(int), print_integer);
			if ( ((ptd[i]).pipelined_peer_requests)[j] == NULL) {
				printf("Error allocating memory for ppipeleined peer request vector. \n.");
				exit(EXIT_FAILURE);
			}
		}
		(ptd[i]).pipelined_peer_requests_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
		if ((ptd[i]).pipelined_peer_requests_mutex == NULL) {
			printf("Error allocating memory for pipelined peer requests vector. %s.\n", strerror(errno));
		}
		pthread_mutex_init( (ptd[i]).pipelined_peer_requests_mutex, NULL);

        }				
}
