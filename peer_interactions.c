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

void print_integer(void *integer)
{
	int *i = (int *)integer;
	printf("%d", *i);
}

struct peer_interactions_thread_data *
get_peer_interactions_thread_data_structures(
		int peer_interactions_thread_count,
		int NoOfPeers,
		struct binary_tree *peers_tree,
		int max_number_of_threads,
		uint8_t *info_hash,
		uint8_t *peer_id)
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
	pitd->NoOfPeers = 0;
	pitd->info_hash = info_hash;
	pitd->info_hash_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if (( pitd->info_hash_mutex) == NULL) {
		printf("Error allocating memory for info_hash mutex. %s.\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	pthread_mutex_init(pitd->info_hash_mutex, NULL);

	pitd->peer_id = peer_id;
	pitd->peer_id_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if ((pitd->peer_id_mutex) == NULL) {
		printf("Error allocatin memory for peer_id_mutex.%s.\n",
				strerror(errno));
		exit(EXIT_FAILURE);
	}
	pthread_mutex_init(pitd->peer_id_mutex, NULL);
	pitd->allocation_and_free_mutex =(pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if ( (pitd->allocation_and_free_mutex) == NULL ) {
		printf("Error allocating memory for mutex to avoid memory manipulation race conditions.%s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	pthread_mutex_init(pitd->allocation_and_free_mutex, NULL);
	pitd->recv_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if ((pitd->recv_mutex) == NULL) {
		printf("Error allocating memory for recv call sychronization.%s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	pthread_mutex_init(pitd->recv_mutex, NULL);
	pitd->poll_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if ((pitd->poll_mutex) == NULL) {
		printf("Error allocating memory for poll mutex.%s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	pthread_mutex_init(pitd->poll_mutex, NULL);
	pitd->NoOfPeers_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if ((pitd->NoOfPeers_mutex) == NULL) {
		printf("Error allocating memory for NoOfPeers_mutex. %s.\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	pthread_mutex_init(pitd->NoOfPeers_mutex, NULL);
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
		(ptd[i]).conn_state = NULL;
		(ptd[i]).conn_state_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
		if ( (ptd[i]).conn_state_mutex == NULL) {
			printf("Error allocating memory for connection state mutexes, %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}	
		pthread_mutex_init((ptd[i]).conn_state_mutex, NULL);
		(ptd[i]).pipelined_peer_requests = NULL;
		(ptd[i]).pipelined_peer_requests_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
		if ((ptd[i]).pipelined_peer_requests_mutex == NULL) {
			printf("Error allocating memory for pipelined peer requests vector. %s.\n", strerror(errno));
		}
		pthread_mutex_init( (ptd[i]).pipelined_peer_requests_mutex, NULL);
        	(ptd[i]).down_rates = NULL;
		(ptd[i]).down_rates_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
		if ( ((ptd[i]).down_rates_mutex) == NULL) {
			printf("Error allocating memory for download rates mutex.%s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		pthread_mutex_init((ptd[i]).down_rates_mutex, NULL);
		(ptd[i]).up_rates = NULL;
		(ptd[i]).up_rates_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
		if ( (ptd[i]).up_rates_mutex == NULL ) {
			printf("Error allocating memory for uoload rates mutex.%s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		(ptd[i]).handshake_completed = 0;
		(ptd[i]).hshake_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
		if ( ((ptd[i]).hshake_mutex) == NULL ) {
			printf("Error allocating mutex for determining which peer connections have completed handhshakes.\n");
			exit(EXIT_FAILURE);
		}
		pthread_mutex_init((ptd[i]).hshake_mutex, NULL);
		(ptd[i]).peer_pieces = 0;
		(ptd[i]).peer_pieces_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
		if ( (ptd[i]).peer_pieces_mutex == NULL ) {
			printf("Error allocating memory for peer_pieces_mutex.\n");
			exit(EXIT_FAILURE);
		}
		pthread_mutex_init((ptd[i]).peer_pieces_mutex, NULL);
		(ptd[i]).extension_protocol_supported = 0;
		(ptd[i]).extension_protocol_supported_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
		if ( (ptd[i]).extension_protocol_supported_mutex == NULL ) {
			printf("Error allocating memory for extension_supported_mutex.%s.\n.",
			       strerror(errno));
			exit(EXIT_FAILURE);
		}
		pthread_mutex_init((ptd[i]).extension_protocol_supported_mutex, NULL);
	}				
	return ptd;
}

void *peer_interactions(void *d)
{
        struct peer_interactions_thread_data *ptd = (struct peer_interactions_thread_data *)d;
	int NoOfPeers = vector_get_size(ptd->peers);
	int *client_socket_fd = (int *)malloc(sizeof(int)*NoOfPeers);
	if (client_socket_fd == NULL) {
		printf("Error allocating memory for client socket file"
		     " discriptors that are used to interact with peers.%s.\n",
		       strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (pthread_mutex_lock(ptd->peers_vector_mutex)!=0) {
		printf("Error locking peers_vector mutex.\n");
		exit(EXIT_FAILURE);
	}
	for (int i=0; i<NoOfPeers; ++i) {
		struct peer *curr_peer = (struct peer *)vector_read(ptd->peers, 
								    i);
		int domain = 0;
		if ((curr_peer->ip_version) == 4) {
			domain = AF_INET;
		} 
		else if ( (curr_peer->ip_version) == 6) {
			domain = AF_INET6;
		}		
		// create socket with appropriate domain
		client_socket_fd[i] = socket(domain, SOCK_STREAM, 6);
	        if ((client_socket_fd[i])== -1)	{
			printf("Error creating socket client side socket for"
			       " client-peer tcp connection.%s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		int curr_fd_status_flags = fcntl(client_socket_fd[i],
						F_GETFL);
		if (curr_fd_status_flags == -1) {
			printf("Error getting file discriptor status flags"
			       " during initialization of client-peer connection.%s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		curr_fd_status_flags |= O_NONBLOCK;
		if (fcntl(client_socket_fd[i], F_SETFL, curr_fd_status_flags)==-1) {
			printf("Error setting socket file discriptor status to"
			       " nonblocking during initialization of client-p"
			       "eer connection.%s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		struct sockaddr peer_address;
		if ((curr_peer->ip_version) == 4) {
			struct sockaddr_in *p = (struct sockaddr_in *)&peer_address;
			p->sin_family = AF_INET;
			p->sin_port = htons(curr_peer->port);
			memcpy(&((p->sin_addr).s_addr), 
			       curr_peer->ip_addr, 4);
		}
		else if ( (curr_peer->ip_version)==6) {
			struct sockaddr_in6 *p = (struct sockaddr_in6 *)&peer_address;
			p->sin6_family = AF_INET6;
			p->sin6_port = htons(curr_peer->port);
			p->sin6_flowinfo = 1; // testing with default value of 1
			memcpy(&((p->sin6_addr).s6_addr),
			       curr_peer->ip_addr,
			       16);
			p->sin6_scope_id = 0; // unspecified NIC interface index
					      //system will determine interface
					      //to use
		}
		socklen_t peer_addr_len = (socklen_t)sizeof(struct sockaddr);
		if ((curr_peer->ip_version) == 4) {
			uint32_t raw_peer_addr = ((curr_peer->ip_addr)[0] << 24) +
					     ((curr_peer->ip_addr)[1] << 16) +
					     ((curr_peer->ip_addr)[2] << 8) +
					     ((curr_peer->ip_addr)[3]);
			struct in_addr peer_addr;
			peer_addr.s_addr = raw_peer_addr; 

			printf("Connecting to peer %s....\n", inet_ntoa(peer_addr));
		}
		else if ( (curr_peer->ip_version)==6) {
			printf("Connecting to peer %x%x:%x%x:%x%x:%x%x:"
						 "%x%x:%x%x:%x%x:%x%x....\n",
				(curr_peer->ip_addr)[0], (curr_peer->ip_addr)[1],
				(curr_peer->ip_addr)[2], (curr_peer->ip_addr)[3],
				(curr_peer->ip_addr)[4], (curr_peer->ip_addr)[5],
				(curr_peer->ip_addr)[6], (curr_peer->ip_addr)[7],
				(curr_peer->ip_addr)[8], (curr_peer->ip_addr)[9],
				(curr_peer->ip_addr)[10], (curr_peer->ip_addr)[11],
				(curr_peer->ip_addr)[12], (curr_peer->ip_addr)[13],
				(curr_peer->ip_addr)[14], (curr_peer->ip_addr)[15]);
		}
		int conn_res = connect(client_socket_fd[i],
				       (struct sockaddr *)&peer_address,
				       peer_addr_len);
		if (conn_res != 0) {
			struct pollfd polld;
                        polld.fd = client_socket_fd[i];
                        polld.events = POLLOUT;
			int ms_timeout = 4000;
                        int poll_res = poll(&polld, 1, ms_timeout);
                        if ((poll_res == 0) || (poll_res == -1)) {
				if (poll_res == -1) {
					printf("Error waiting to connect to peer via call to poll. %s.\n",
						strerror(errno));
				}
				if (poll_res == 0) {
					printf("Error waiting to connect to peer. Timeout expired of %dms.\n", ms_timeout);
				}
                                if ( close(client_socket_fd[i]) == -1) {
                                        printf("Error closing client socket file descriptor after failing to connect to peer.%s.\n", strerror(errno));
                                }
                                client_socket_fd[i] = -1;
                                continue;
                        }
			else if ((polld.revents & POLLOUT) > 0) {
				int error_val = -1;
				socklen_t error_val_len = (socklen_t)sizeof(int);
				if ( getsockopt(client_socket_fd[i],
						SOL_SOCKET,
						SO_ERROR,
						&error_val,
						&error_val_len) == -1) {
					printf("Error obtaining SO_ERROR for previois connect call. %s.\n", strerror(errno));
					if ( close(client_socket_fd[i]) == -1) {
						printf("Error closing client socket file descriptor after failing to connect to peer.%s.\n", strerror(errno));
					}
					client_socket_fd[i] = -1;
					continue;
				}
				if (error_val_len != ((socklen_t)sizeof(int))) {
					printf("Error obtaining SO_ERROR for previois connect call. SO_ERROR return type misatch.%s.\n", strerror(errno));
					if ( close(client_socket_fd[i]) == -1) {
						printf("Error closing client socket file descriptor after failing to connect to peer.%s.\n", strerror(errno));
					}
					client_socket_fd[i] = -1;
					continue;
				}
				if (error_val != 0) {
					printf("Error during connect call. %s\n", strerror(error_val));
					if ( close(client_socket_fd[i]) == -1) {
						printf("Error closing client socket file descriptor after failing to connect to peer.%s.\n", strerror(errno));
					}
					client_socket_fd[i] = -1;
					continue;
				}
				// connect successfull. Reset socket back to blocking
				curr_fd_status_flags &= (~O_NONBLOCK);
				if (fcntl(client_socket_fd[i], F_SETFL, curr_fd_status_flags)==-1) {
					printf("Error setting socket file discriptor status to"
					       " nonblocking during initialization of client-p"
					       "eer connection.%s\n", strerror(errno));
					if ( close(client_socket_fd[i]) == -1) {
                                                printf("Error closing client socket file descriptor after failing to connect to peer.%s.\n", strerror(errno));
                                        }
                                        client_socket_fd[i] = -1;
                                        continue;
				}
				if ((curr_peer->ip_version) == 4) {
					uint32_t raw_peer_addr = ((curr_peer->ip_addr)[0] << 24) +
							     ((curr_peer->ip_addr)[1] << 16) +
							     ((curr_peer->ip_addr)[2] << 8) +
							     ((curr_peer->ip_addr)[3]);
					struct in_addr peer_addr;
					peer_addr.s_addr = raw_peer_addr;

					printf("Connected to peer %s.\n", inet_ntoa(peer_addr));
				}
				else if ( (curr_peer->ip_version)==6) {
					printf("Connected to peer %x%x:%x%x:%x%x:%x%x:"
								 "%x%x:%x%x:%x%x:%x%x.\n",
						(curr_peer->ip_addr)[0], (curr_peer->ip_addr)[1],
						(curr_peer->ip_addr)[2], (curr_peer->ip_addr)[3],
						(curr_peer->ip_addr)[4], (curr_peer->ip_addr)[5],
						(curr_peer->ip_addr)[6], (curr_peer->ip_addr)[7],
						(curr_peer->ip_addr)[8], (curr_peer->ip_addr)[9],
						(curr_peer->ip_addr)[10], (curr_peer->ip_addr)[11],
						(curr_peer->ip_addr)[12], (curr_peer->ip_addr)[13],
						(curr_peer->ip_addr)[14], (curr_peer->ip_addr)[15]);


				}
			}
			else {
				printf("Error client socket fd not ready to write after poll returned.\n");
				if ( close(client_socket_fd[i]) == -1) {
                                        printf("Error closing client socket file descriptor after failing to connect to peer.%s.\n", strerror(errno));
                                }
                                client_socket_fd[i] = -1;
                                continue;
			}
		}
		else {
			if ((curr_peer->ip_version) == 4) {
				uint32_t raw_peer_addr = ((curr_peer->ip_addr)[0] << 24) +
						     ((curr_peer->ip_addr)[1] << 16) +
						     ((curr_peer->ip_addr)[2] << 8) +
						     ((curr_peer->ip_addr)[3]);
				struct in_addr peer_addr;
				peer_addr.s_addr = raw_peer_addr;

				printf("Connected to peer %s.\n", inet_ntoa(peer_addr));
			}
			else if ( (curr_peer->ip_version)==6) {
				printf("Connected to peer %x%x:%x%x:%x%x:%x%x:"
							 "%x%x:%x%x:%x%x:%x%x.\n",
					(curr_peer->ip_addr)[0], (curr_peer->ip_addr)[1],
					(curr_peer->ip_addr)[2], (curr_peer->ip_addr)[3],
					(curr_peer->ip_addr)[4], (curr_peer->ip_addr)[5],
					(curr_peer->ip_addr)[6], (curr_peer->ip_addr)[7],
					(curr_peer->ip_addr)[8], (curr_peer->ip_addr)[9],
					(curr_peer->ip_addr)[10], (curr_peer->ip_addr)[11],
					(curr_peer->ip_addr)[12], (curr_peer->ip_addr)[13],
					(curr_peer->ip_addr)[14], (curr_peer->ip_addr)[15]);


			}
		}
	}
	if (pthread_mutex_unlock(ptd->peers_vector_mutex)!=0) {
                printf("Error unlocking peers_vector mutex.\n");
                exit(EXIT_FAILURE);
        }
	int NoOfConnectedPeers = 0;
	for (int i=0; i<NoOfPeers; ++i) {
		if ((client_socket_fd[i]) != -1) {
			++NoOfConnectedPeers;
		}
	}
	printf("Number of connected peers for current thread: %d\n",NoOfConnectedPeers);

	if (pthread_mutex_lock((ptd->thread_independent_data)->NoOfPeers_mutex) != 0) {
		printf("Error locking peers_vector_mutex.\n");
		exit(EXIT_FAILURE);
	}
	(ptd->thread_independent_data)->NoOfPeers += NoOfConnectedPeers;
	if (pthread_mutex_unlock((ptd->thread_independent_data)->NoOfPeers_mutex) != 0) {
		printf("Error unlocking peers_vector_mutex after obtaining connected peers.\n");
		exit(EXIT_FAILURE);
	}
	if (pthread_mutex_lock(ptd->peers_vector_mutex) != 0 ) {
		printf("Error lcoking peers_vector_mutex to edit peers_vector.\n");
		exit(EXIT_FAILURE);
	}
	struct vector *connected_peers = vector_null_init(sizeof(struct peer), print_peer);
	int *new_client_socket_fd = (int *)malloc(sizeof(int)*NoOfConnectedPeers);
	if (new_client_socket_fd == NULL) {
		printf("Error allocating memory for connected file discriptors.%s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	int index = 0;
	for (int i=0; i<NoOfPeers; ++i) {
		if (client_socket_fd[i] != -1) {
			struct peer *curr_connected_peer = vector_read(ptd->peers, i);
			vector_push_back(connected_peers, curr_connected_peer);
			new_client_socket_fd[index] = client_socket_fd[i];
			++index;
		}
	}
	vector_free(ptd->peers);
	ptd->peers = connected_peers;
	free(client_socket_fd);
	client_socket_fd = new_client_socket_fd;
	if ( pthread_mutex_unlock(ptd->peers_vector_mutex) != 0) {
		printf("Error releasing mutex for peers_vector.\n");
	}
	struct connection_ci_state *conn_state = (struct connection_ci_state *)malloc(sizeof(struct connection_ci_state)*NoOfConnectedPeers);
	for (int i=0; i<NoOfConnectedPeers; ++i) {
		(conn_state[i]).client_choke_state = 0; 
                (conn_state[i]).client_interested_state = 0;
                (conn_state[i]).peer_choke_state = 0;
                (conn_state[i]).peer_interested_state = 0;
	}	
	if ( pthread_mutex_lock(ptd->conn_state_mutex) != 0) {
		printf("Error locking mutex for adjusting connection state.\n");
	        exit(EXIT_FAILURE);	
	}	
	ptd->conn_state = conn_state;
	if ( pthread_mutex_unlock(ptd->conn_state_mutex) != 0) {
		printf("Error releasing mutex for connection state.\n");
		exit(EXIT_FAILURE);
	}
	struct vector **pipelined_requests = (struct vector **)malloc(sizeof(struct vector *)*NoOfConnectedPeers);
	if (pipelined_requests == NULL) {
		printf("Error allocating memory to store pipelined requests.%s.\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	for (int i=0; i<NoOfConnectedPeers; ++i) {
		pipelined_requests[i] = vector_null_init(sizeof(int), print_integer);
	}
	if (pthread_mutex_lock(ptd->pipelined_peer_requests_mutex) != 0) {
                printf("Error locking mutex for initializing pipeline requests vector.\n");
                exit(EXIT_FAILURE);
        }
	ptd->pipelined_peer_requests = pipelined_requests;
	if (pthread_mutex_unlock(ptd->pipelined_peer_requests_mutex) != 0) {
                printf("Error unlocking mutex for initializing pipeline requests vector.\n");
                exit(EXIT_FAILURE);
        }
	struct data_transfer_rate *d_rate = (struct data_transfer_rate *)malloc(sizeof(struct data_transfer_rate)*NoOfConnectedPeers);
	if (d_rate==NULL) {
		printf("Error allocating memory for download rates.%s.\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	for (int i=0; i<NoOfConnectedPeers; ++i) {
		(d_rate[i]).previous_transfer_rate = 0; 
                (d_rate[i]).curr_data_transferred = 0;
	}
	if (pthread_mutex_lock(ptd->down_rates_mutex) != 0) {
		printf("Error locking download rates mutex for initializing down rates.\n");
		exit(EXIT_FAILURE);
	}
	ptd->down_rates = d_rate;
	if (pthread_mutex_unlock(ptd->down_rates_mutex) != 0) {
                printf("Error unlocking download rates mutex after initializing down rates.\n");
                exit(EXIT_FAILURE);
        }
	struct data_transfer_rate *u_rate = (struct data_transfer_rate *)malloc(sizeof(struct data_transfer_rate)*NoOfConnectedPeers);
        if (u_rate==NULL) {
                printf("Error allocating memory for download rates.%s.\n",
                        strerror(errno));
                exit(EXIT_FAILURE);
        }
        for (int i=0; i<NoOfConnectedPeers; ++i) {
                (u_rate[i]).previous_transfer_rate = 0;
                (u_rate[i]).curr_data_transferred = 0;
        }
        if (pthread_mutex_lock(ptd->up_rates_mutex) != 0) {
                printf("Error locking download rates mutex for initializing down rates.\n");
                exit(EXIT_FAILURE);
        }
        ptd->up_rates = u_rate;
        if (pthread_mutex_unlock(ptd->up_rates_mutex) != 0) {
                printf("Error unlocking download rates mutex after initializing down rates.\n");
                exit(EXIT_FAILURE);
        }
	if (pthread_mutex_lock(ptd->hshake_mutex) != 0) {
		printf("Error locking handshake mutex.\n");
		exit(EXIT_FAILURE);
	}
	ptd->handshake_completed = (uint8_t *)malloc(NoOfConnectedPeers);
	for (int i=0; i<NoOfConnectedPeers; ++i) {
		(ptd->handshake_completed)[i] = 0; // handshale yet to be completed
	}
	if (pthread_mutex_unlock(ptd->hshake_mutex) != 0) {
		printf("Error unlicking handshake mutex.\n");
		exit(EXIT_FAILURE);
	}
	ptd->peer_pieces = (struct vector **)malloc(sizeof(struct vector *)*NoOfConnectedPeers);
	if ((ptd->peer_pieces) == NULL) {
		printf("Error allocating memory for peer_pieces vector.\n");
		exit(EXIT_FAILURE);
	}
	for (int i=0; i<NoOfConnectedPeers; ++i) {
		(ptd->peer_pieces)[i] = vector_null_init(sizeof(int), print_integer);
	}
	ptd->extension_protocol_supported = (uint8_t *)malloc(NoOfConnectedPeers);
	for (int i=0; i<NoOfConnectedPeers; ++i) {
		(ptd->extension_protocol_supported)[i] = 0; // default not supported
	}
	// main interaction loop
	uint8_t info_dict_obtained = 0;
	while (1) {
		if (pthread_mutex_lock(ptd->peers_vector_mutex) != 0) {
			printf("Error locking mutex for access to connected peers.\n");
			exit(EXIT_FAILURE);
		}
		NoOfConnectedPeers = vector_get_size(ptd->peers);
		if (pthread_mutex_unlock(ptd->peers_vector_mutex) != 0) {
			printf("Error uncloking peers vector mutex after"
			       " obtaining the number of connected peers.\n");
			exit(EXIT_FAILURE);
		}
		if (!info_dict_obtained) {
			if (pthread_mutex_lock((ptd->thread_independent_data)->info_dict_mutex)!=0) {
				printf("Error acquiring mutex for info_dict to see if it has already been obtained.\n");
				exit(EXIT_FAILURE);
			}
			if (((ptd->thread_independent_data)->info_dict) != 0) {
				info_dict_obtained = 1;
			}
			if ( pthread_mutex_unlock((ptd->thread_independent_data)->info_dict_mutex) != 0) {
				printf("Error unlocking info dict mutex.\n");
				exit(EXIT_FAILURE);
			}
		}
		for (int i=0; i<NoOfConnectedPeers; ++i) {
			if (client_socket_fd[i] == -1) {
				continue;
			}
			if (pthread_mutex_lock(ptd->hshake_mutex) != 0) {
				printf("Error locking handhsake mutex to see if"
				       " peer connection has completed initial"
				       " handshake.\n");
				exit(EXIT_FAILURE);
			}
			if ( ((ptd->handshake_completed)[i]) == 0) {
				// handshake not completed for this peer
				uint8_t handshake[68];
				handshake[0] = 19;
				char *bittorrent_protocol_string = "BitTorrent protocol";
				memcpy(&(handshake[1]),
				       bittorrent_protocol_string,
				       strlen(bittorrent_protocol_string));
				memset(&(handshake[20]), 0, 8);							
				handshake[25] = 0x10; // client supports BEP10
				memcpy(&(handshake[28]), 
				       (ptd->thread_independent_data)->info_hash,
				       20);
				memcpy(&(handshake[48]),
				       (ptd->thread_independent_data)->peer_id,
                                       20);
				int send_res = send(client_socket_fd[i],
				     	  	    handshake,
				     	  	    68,
				     	            0);
			        if (send_res == -1) {
					printf("Error sending initial BitTorrent handshake.\n");
					if ( pthread_mutex_unlock(ptd->hshake_mutex) != 0) {
                                		printf("Error unlocking handshake mutex.\n");
					}
					continue;
				}
				else if (send_res != 68) {
					printf("Error sending initial BitTorrnet handshake."
					       " Unexpected number of bytes sent.\n");
					if ( pthread_mutex_unlock(ptd->hshake_mutex) != 0) {
                                                printf("Error unlocking handshake mutex.\n");
                                        }
                                        continue;
				}
				// Hnadshake sent
				memset(handshake, 0, 68); // reset handshake to zero
				// recv handshake from peer
				int handshake_bytes_read = 0;
				uint8_t error_reading_bytes = 0;
				uint8_t error_whilst_waiting = 0;
				uint8_t timeout_occurred = 0;
				while (handshake_bytes_read != 68) {
					struct pollfd polld;
					polld.fd = client_socket_fd[i];
					polld.events = POLLIN;
					int poll_res = poll(&polld, 1, 2000);
					if (poll_res == 0) {
						//timeout occurred
						timeout_occurred = 1;
						break;
					}
					else if (polld.revents & POLLIN) {
						int bytes_read = recv(client_socket_fd[i],
					     	     		&(handshake[handshake_bytes_read]),
					             		68-handshake_bytes_read, 0);
						if (bytes_read == -1) {
							printf("Error receiving handshake bytes. %s."
							       "\n", strerror(errno));
							error_reading_bytes = 1;
							break;
						}
						handshake_bytes_read += bytes_read;
					}
					else {
					 // some error occurred whist waiting for bytes
						error_whilst_waiting = 1;
						printf("Error occurred whilst waiting for handshake"
							" from peer.\n");
						break;
					}
				}
				if (timeout_occurred) {
					printf("Timeout occurred whilst waiting for initial "
					       "handshake bytes.\n");
					if ( pthread_mutex_unlock(ptd->hshake_mutex) != 0) {
                        	        	printf("Error unlocking handshake mutex.\n");
                	        	        exit(EXIT_FAILURE);
		                        }
					continue;
				}
				if (error_reading_bytes) {
					if ( pthread_mutex_unlock(ptd->hshake_mutex) != 0) {
                                                printf("Error unlocking handshake mutex.\n");
                                                exit(EXIT_FAILURE);
                                        }
                                        continue;
				}
				if (error_whilst_waiting) {
					if ( pthread_mutex_unlock(ptd->hshake_mutex) != 0) {
                                                printf("Error unlocking handshake mutex.\n");
                                                exit(EXIT_FAILURE);
                                        }
                                        continue;
				}
				// handshake bytes has been received
				uint8_t info_hash_match = 1;
				for (int i=0; i<20; ++i) {
					if (handshake[28+i] != 
					    ((ptd->thread_independent_data)->info_hash)[i]) {
						info_hash_match = 0;
						break;
					}
				}
				if (!info_hash_match) {
					printf("Info hash received from peer does not match local "
						"info hash retrieved from tracker.\n");
					if ( pthread_mutex_unlock(ptd->hshake_mutex) != 0) {
                                                printf("Error unlocking handshake mutex.\n");
                                                exit(EXIT_FAILURE);
                                        }
                                        continue;
				}
				//info hash matches
				(ptd->handshake_completed)[i] = 1;
				if (pthread_mutex_unlock(ptd->hshake_mutex) != 0) {
					printf("Error releasing handshake mutex after completing initial"
					       " BitTorrent handshake.\n");
					exit(EXIT_FAILURE);
				}
				if (handshake[25] == 0x10) {
				 	if (pthread_mutex_lock(ptd->extension_protocol_supported_mutex) != 0) {
						printf("Error locking extension protocol support mutex.\n");
						exit(EXIT_FAILURE);
					}	
					(ptd->extension_protocol_supported)[i] = 1;
					if (pthread_mutex_unlock(ptd->extension_protocol_supported_mutex) != 0) {
                                                printf("Error locking extension protocol support mutex.\n");
                                                exit(EXIT_FAILURE);
                                        }
				}	
			}
			if ( pthread_mutex_unlock(ptd->hshake_mutex) != 0) {
				printf("Error unlocking handshake mutex.\n");
				exit(EXIT_FAILURE);
			}
			// BitTorrent Handshake completed
			if (!info_dict_obtained) {
				int bytes_read = 0;
				uint8_t *recv_data = recv_packet(client_socket_fd[i],
								 &bytes_read,
							 	 4000, // 4 second timeout (4000ms)
						   (ptd->thread_independent_data)->recv_mutex,
                                                   (ptd->thread_independent_data)->poll_mutex,
						   (ptd->thread_independent_data)->allocation_and_free_mutex);
				if (bytes_read) {
					printf("Received packet of message type:%d....\n", recv_data[4]);
					write(1, recv_data, bytes_read);
					printf("  \n");
					exit(EXIT_SUCCESS);
				}
				else {
					printf("Failed to receive packet.\n");
					exit(EXIT_FAILURE);
				}
							  	 
			}	
		}
	}	
}
