/*=======================================;
 *
 * File: peers.c
 * Content: Implementation of the structures
 * and functions in the peers.h header file.
 * These functions and structs are used
 * to obtain a maximial list of peers.
 * Date: 12/6/2025
 *
 *****************************************/
#include "peers.h"
struct peer
{
	char *peer_id;
	uint8_t *ip_addr;
	uint8_t ip_version;
	uint16_t port;
};

void start_rand()
{
	time_t curr_time = time(NULL);
        if (curr_time == ((time_t)-1)) {
                printf("Error calling time(NULL) to obtain psuedo random integer. %s\n", strerror(errno));
                return;
        }
        else {
                srand(curr_time);
        }
}

void *compare_peers(void *p1, void *p2)
{
	struct peer *peer1 = (struct peer *)p1;
	struct peer *peer2 = (struct peer *)p2;
	if ((peer1->ip_version) < (peer2->ip_version)) {
		return peer2; // peer1 ip version is 4 while peer2 ip version 
			      // is 6
	}
	else if  ( (peer2->ip_version) < (peer1->ip_version)) {
		return peer1; // peer2 ip version ia 4 with peer1 ip version 6
	}
	else {
		// either both are v6 or both are v4
		if ((peer1->ip_version) == 4) {
			uint8_t res = 0;
			for (int i=0; i<4; ++i) {
				if ( (peer1->ip_addr)[i] < (peer2->ip_addr)[i]) {
					return peer2;
				}
				else if ( (peer2->ip_addr)[i] < 
					  (peer1->ip_addr)[i] ) {
					return peer1;
				}
			}
			if ((peer1->port) < (peer2->port)) {
				return peer2;
			}
			else if ( (peer2->port) < (peer1->port) ) {
				return peer1;
			}
			return 0; // both peer1 and peer2 have identical ip
				    // addresses and ports
		}
		else if ( (peer1->ip_version) == 6) {
			uint8_t res = 0;
			for (int i=0; i<16; ++i) {
				if ( (peer1->ip_addr)[i] < (peer2->ip_addr)[i]) {
					return peer2;
				}
				else if ( (peer2->ip_addr)[i] < (peer1->ip_addr)[i]) {
					return peer1;
				}
			}
			if ( (peer1->port) < (peer2->port) ) {
				return peer2;
			}
			else if ( (peer2->port) < (peer1->port) ) {
				return peer1;
			}
			return 0;
		}
	}
}

void print_peer(void *p) 
{
	struct peer *peer = (struct peer *)p;
	if ((peer->ip_version) == 6) {
		for (int i=0; i<8; ++i) {
			uint16_t curr_ushort = 0;
			curr_ushort += ( ((peer->ip_addr)[i*2]) << 8);
			curr_ushort += (peer->ip_addr)[(i*2) + 1];
			printf("%u", curr_ushort);
			if (i<7) {
				printf(":");
			}
		}
	}
	else if ( (peer->ip_version) == 4) {
		for (int i=0; i<4; ++i) {
			printf("%u", (peer->ip_addr)[i]);
			if (i<3) {
				printf(".");
			}
		}	
	}
	else {
		printf("Unsupported ip version (requires a value of 4 or 6)");
		exit(EXIT_FAILURE);
	}
	if ((peer->port) > 0 ) {
		printf(":%u", peer->port);
	}
}


int udp_peer_discovery_request_ms_to_timeout(int n)
{
	double y = n;
	double x = 2.0;
	double val = 15.0;
	val *= pow(x,y);
	int res = 1000*val;
	return res;
}

uint8_t *generate_peer_id()
{
	uint8_t *peer_id = (uint8_t *)malloc(20);
	if (peer_id ==NULL) {
		printf("Error allocating memorory for clinet peer_id. %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	peer_id[0] = 'M';
	peer_id[1] = '0';
	peer_id[2] = '-';
	peer_id[3] = '1';
	peer_id[4] = '-';
	peer_id[5] = '0';
	peer_id[6] = '-';
	peer_id[7] = '-';
	for (int i=8; i<20; ++i) {
		peer_id[i] = (rand() % 256);
	}
	return peer_id;
}

void fill_peer_discovery_thread_structures(struct peer_discovery_thread_data *pdt,
                                           int NoOfTrackers,
                                           int no_of_peer_discovery_threads,       
   					   int max_number_of_threads, 
					   struct vector *tracker_vect,  
					   uint8_t *info_hash,
					   uint8_t *peer_id,
					   pthread_mutex_t *access_peers_tree_mutex)
{
	for (int i=0; i<no_of_peer_discovery_threads; ++i) {
                (pdt[i]).trackers_vector = vector_null_init(sizeof(struct tracker), print_tracker);
        }
        int base_no_of_trackers = NoOfTrackers/(max_number_of_threads - 1);
        int tracker_index = 0;
        for (int i=0; i<no_of_peer_discovery_threads; ++i) {
                if (base_no_of_trackers > 0) {
                        if (i<(no_of_peer_discovery_threads - 1)) {
                                for (int j=0; j<base_no_of_trackers; ++j) {
                                        struct tracker *curr_tracker = (struct tracker *)vector_read(tracker_vect, tracker_index+j);
                                        vector_push_back( (pdt[i]).trackers_vector, curr_tracker);
                                }
                        }
                        else {
                                for (int j=tracker_index; j<NoOfTrackers; ++j) {
                                        struct tracker *curr_tracker = (struct tracker *)vector_read(tracker_vect, j);
                                        vector_push_back( (pdt[i]).trackers_vector, curr_tracker);
                                }
                        }
                        tracker_index += base_no_of_trackers;
                }
                else {
                        struct tracker *curr_tracker = (struct tracker *)vector_read(tracker_vect, tracker_index);
                        vector_push_back( (pdt[i]).trackers_vector, curr_tracker);
                        ++tracker_index;
                }
        }
        struct binary_tree *peers_tree = init_null_btree(sizeof(struct peer), compare_peers, print_peer);
        pthread_mutex_init(access_peers_tree_mutex, NULL);
        for (int i=0; i<no_of_peer_discovery_threads; ++i) {
                (pdt[i]).info_dict_sha1_hash = info_hash;
		(pdt[i]).peer_id = peer_id;
		(pdt[i]).peers_tree = peers_tree;
		(pdt[i]).access_peers_tree_mutex = access_peers_tree_mutex; 
        }

}

void obtain_peer_list_from_tracker_host(struct addrinfo *tracker_addr,
                                        struct binary_tree *peers_tree,
                                        pthread_mutex_t *peers_access_mutex,
					uint8_t *info_dict_sha1_hash,
					uint8_t *peer_id)
{
	if ( (tracker_addr->ai_family != AF_INET) && 
	     (tracker_addr->ai_family != AF_INET6) ) {
		return; // unsupported address family type
	}
	else {  // create client socket to match remote tracker socket with udp
		// service
		printf("Obtaining ip version for local host - tracker connection...\n");
		uint8_t ip_version = 0;
		if (tracker_addr->ai_family == AF_INET) {
			ip_version = 4;
			printf("IP version 4 present\n");
		}
		else if ( tracker_addr->ai_family == AF_INET6 ) {
			ip_version = 6;
			printf("IP version 6 present\n");
		}
		int client_socket_fd = socket(tracker_addr->ai_family,
				              tracker_addr->ai_socktype,
					      tracker_addr->ai_protocol);
		if (client_socket_fd == -1) {
			printf("Error obtaining client socket for communication to tracker. %s.\n", strerror(errno));
			return;
		}
		if (connect(client_socket_fd, 
			    tracker_addr->ai_addr, 
			    tracker_addr->ai_addrlen)==-1) {
			printf("Error associating remote udp tracker socket to client socket during peer discovery. %s\n", strerror(errno));
			return;
		}
		uint8_t protocol_id[8] = {0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80};
		uint8_t action[4];
		memset(action, 0, 4);
		uint8_t transaction_id[4];
		for (int i=0; i<4; ++i) {
			transaction_id[i] = (rand() % 256);
		}
		uint8_t connect_request[16];
		uint8_t connect_response[16];
		memcpy(connect_request, protocol_id, 8);
		memcpy(&(connect_request[8]), action, 4);
		uint8_t peer_list_obtained = 0;
		uint8_t *peer_list;
		int no_of_peers = -1;
		int n = 0;
		time_t connect_id_receipt_time;
		time_t curr_time;
		int announce_response_buffer_len = 0;
		uint8_t *announce_response_buffer = (uint8_t *)malloc(300000);
		if (announce_response_buffer == NULL) {
			printf("Error allocating temporary announce response buffer.%s.\n", strerror(errno));
			return;
		}
		int bytes_read = 0;
		uint8_t peer_address_size = 0;
		while (!peer_list_obtained) {
			memcpy(&(connect_request[12]), transaction_id, 4);
			if (ip_version == 4) {
				printf("Sending connect request packet to tracker %s..\n", inet_ntoa(((struct sockaddr_in *)tracker_addr->ai_addr)->sin_addr));
			}
			else if (ip_version == 6) {
				uint8_t *trk_v6_addr = (((struct sockaddr_in6 *)tracker_addr->ai_addr)->sin6_addr).s6_addr;
				printf("Sending connect request packet to tracker %x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x..\n", trk_v6_addr[0], trk_v6_addr[1], 
						                                                                                trk_v6_addr[2], trk_v6_addr[3],
																trk_v6_addr[4], trk_v6_addr[5],
                                                                                                                                trk_v6_addr[6], trk_v6_addr[7],
																trk_v6_addr[8], trk_v6_addr[9],
                                                                                                                                trk_v6_addr[10], trk_v6_addr[11],
																trk_v6_addr[12], trk_v6_addr[13],
                                                                                                                                trk_v6_addr[14], trk_v6_addr[15]);

			}
			if (send(client_socket_fd, connect_request, 16, 0) == -1) {
				printf("Error sending announce request to tracker during peer discovery over udp.%s\n", strerror(errno));
				return;
			}
			struct pollfd pfd;
			pfd.fd = client_socket_fd;
			pfd.events = POLLIN;
			int poll_res = -1;
			while (1) {
				poll_res = poll(&pfd, 1, udp_peer_discovery_request_ms_to_timeout(n));
				if (poll_res < 0) {
					printf("Error occurred whilst waiting for udp tracker peer discovery connect response. %s\n", strerror(errno));
					return;
				}
				if (poll_res == 0) {
					if (n==8) {
						return;
					}
					++n;
					continue;
				}
				// poll_res > 0
				if ((pfd.revents & (POLLERR + POLLHUP + POLLNVAL))>0) {
					printf("Error occurred whilst waiting for connect response over udp during peer discovery via tracker.\n");
					return;
				}
				// pfd.revents == POLLIN
				bytes_read = 0;
				while (bytes_read < 16) {
					int recv_res = recv(client_socket_fd, &(connect_response[bytes_read]), 16-bytes_read, 0);
					if ( recv_res < 0) {
						printf("Error receiving connect response from tracker for peer discovery. %s\n", strerror(errno));
						return;
					}
					bytes_read += recv_res;
					if (bytes_read < 16) {
						poll_res = poll(&pfd, 1, 3000);
		                                if (poll_res < 0) {
                	                        	printf("Error occurred whilst waiting for udp tracker peer discovery connect response. %s\n", strerror(errno));
                        	                	return;
                                		}
						if (poll_res == 0) {
							printf("Error takien more than 3 seconds to receive 16 bytes of tracker connect response "
							       "during peer discovery protocop over udp.\n");
							return;	
						}
						if ((pfd.revents & (POLLERR + POLLHUP + POLLNVAL))>0) {
                                		        printf("Error occurred whilst waiting for connect response over udp during peer discovery via tracker.\n");
                                        		return;
						}
					}
                                }
				connect_id_receipt_time = time(NULL);
				if (connect_id_receipt_time == ((time_t)-1)) {
					printf("Error obtaining time of connect_id received during peer_discovery over udp. %s.\n", strerror(errno));
					return;
				}
				poll_res = poll(&pfd, 1, 3000);
				if (poll_res < 0) {
					printf("Error whilst receeiving excess bytes in connect response. %s.\n", strerror(errno));
					return;
                                }
				while (poll_res > 0) {
					uint8_t excess_connect_response_data[100];
					if (recv(client_socket_fd, excess_connect_response_data, 100, 0)<0) {
						printf("Error whilst receiving excess connect response data from tracker during peer discovery. %s.\n", strerror(errno));
						return;
					}
					poll_res = poll(&pfd, 1, 3000);
					if (poll_res < 0) {
						printf("Error whilst receeiving excess bytes in connect response. %s.\n", strerror(errno));
						return;
					}
				}
				break;
			}
			if (ip_version == 4) {
				printf("Received connect response packet from tracker %s..\n", inet_ntoa(((struct sockaddr_in *)tracker_addr->ai_addr)->sin_addr));
			}
			else if (ip_version == 6) {
				uint8_t *trk_v6_addr = (((struct sockaddr_in6 *)tracker_addr->ai_addr)->sin6_addr).s6_addr;
                                printf("Received connect response packet from tracker %x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x..\n", trk_v6_addr[0], trk_v6_addr[1],
                                                                                                                                trk_v6_addr[2], trk_v6_addr[3],
                                                                                                                                trk_v6_addr[4], trk_v6_addr[5],
                                                                                                                                trk_v6_addr[6], trk_v6_addr[7],
                                                                                                                                trk_v6_addr[8], trk_v6_addr[9],
                                                                                                                                trk_v6_addr[10], trk_v6_addr[11],
                                                                                                                                trk_v6_addr[12], trk_v6_addr[13],
                                                                                                                                trk_v6_addr[14], trk_v6_addr[15]);
			}
			n=0;
			uint8_t announce_request[98];
			memcpy(announce_request, &(connect_response[8]), 8);
			memset(&(announce_request[8]), 0, 3);
			announce_request[11] = 1; // set action to 1
			for (int i=0; i<4; ++i) {
				announce_request[12+i] = (rand() % 256);
				transaction_id[i] = announce_request[12+i];
			}
			memcpy(&(announce_request[16]), info_dict_sha1_hash, 20);
			memcpy(&(announce_request[36]), peer_id, 20);
			for (int i=0; i<8; ++i) {
				announce_request[56+i] = 0; // downloaded = 0 bytes
			}
			for (int i=0; i<8; ++i) {
				announce_request[64+i] = 255; // left = 2^64 - 1 bytes
			}
			for (int i=0; i<8; ++i) {
				announce_request[72+i] = 0; // uploaded = 0 bytes
			}
			for (int i=0; i<3; ++i) {
				announce_request[80+i] = 0;
			}
			announce_request[83] = 2;
			memset(&(announce_request[84]), 4, 0); // IP Address
			for (int i=0; i<4; ++i) {
				announce_request[88+i] = 0; // key field
			}
			for (int i=0; i<4; ++i) {
				announce_request[92+i] = 255; // number of peers requested
			}
			announce_request[96] = 26;  //
			announce_request[97] = 233; // listen on port 6889 == 0x1AE9
			curr_time = time(NULL);
			if (difftime(curr_time, connect_id_receipt_time) > 60.0) {
				continue;
			}
			double secs_since_connect_id_receipt;
			bytes_read = 0;
			while (1) {
				curr_time = time(NULL);
                        	secs_since_connect_id_receipt = difftime(curr_time, connect_id_receipt_time);
				if (secs_since_connect_id_receipt > 60.0) {
					break;
				}
				if (ip_version == 4) {
					printf("Sending announce request packet to tracker %s..\n", inet_ntoa(((struct sockaddr_in *)tracker_addr->ai_addr)->sin_addr));
				}
				else if (ip_version == 6) {
					uint8_t *trk_v6_addr = (((struct sockaddr_in6 *)tracker_addr->ai_addr)->sin6_addr).s6_addr;
					printf("Sending announce request packet to tracker %x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x..\n", trk_v6_addr[0], trk_v6_addr[1],
																	trk_v6_addr[2], trk_v6_addr[3],
																	trk_v6_addr[4], trk_v6_addr[5],
																	trk_v6_addr[6], trk_v6_addr[7],
																	trk_v6_addr[8], trk_v6_addr[9],
																	trk_v6_addr[10], trk_v6_addr[11],
																	trk_v6_addr[12], trk_v6_addr[13],
																	trk_v6_addr[14], trk_v6_addr[15]);

				}
				if (send(client_socket_fd, announce_request, 98, 0) < 0) {
					printf("Error sending tracker announce request over udp during peer discovery.%s.\n", strerror(errno));
					return;
				}
				bytes_read = 0;
				poll_res = poll(&pfd, 1, udp_peer_discovery_request_ms_to_timeout(n));
				if (poll_res < 0) {
					printf("Error occurred whilst waiting for announce response.%s.\n", strerror(errno));
					return;
				}
				if (poll_res == 0) {
					if (n==8) {
						return;
					}
					++n;
					continue;
				}
				// poll_res > 0
				if ((pfd.revents & (POLLERR + POLLHUP + POLLNVAL))>0) {
                                        printf("Error occurred whilst waiting for announce response over udp during peer discovery via tracker.\n");
                                        return;
                                }
		        	bytes_read = recv(client_socket_fd, announce_response_buffer, 300000, 0);
				if (bytes_read < 0) {
					printf("Error receiving announce response containing peer list.%s.\n", strerror(errno));
					return;
				}
				peer_address_size = 0;
				if (ip_version == 4) {
					peer_address_size = 6;
				}
				else if (ip_version == 6) {
					peer_address_size = 18;
				}
				while ( (bytes_read < (20 + peer_address_size)) || (((bytes_read - 20) % peer_address_size)!=0) ) {
					poll_res = poll(&pfd, 1, 4000);
					if (poll_res < 0) {
						printf("Error waiting for announce response message.%s\n", strerror(errno));
						return;
					}
					if (poll_res == 0) {
						printf("Error, have not received sufficient aamount of data when tracker annpunce response required.\n");
						return;	
					}
					if ((pfd.revents & (POLLERR + POLLHUP + POLLNVAL))>0) {
	                                        printf("Error occurred whilst waiting for announce request bytes over udp during peer discovery via tracker.\n");
        	                                return;
			                }
					int curr_bytes_read = recv(client_socket_fd, &(announce_response_buffer[bytes_read]), 300000 - bytes_read, 0);
					if (curr_bytes_read < 0) {
						printf("Error receiving tracker announce response. %s.\n", strerror(errno));
						return;
					}
					bytes_read += curr_bytes_read;
				}
				poll_res = poll(&pfd, 1, 6000);
				if (poll_res < 0) {
					printf("Error waiting for additional bytes of tracker announce request.  %s.\n", strerror(errno));
					return;
				}
				else if (poll_res == 0) {
					// check for announce action, and transactuib ud
					uint8_t announce_response_valid = 1;
					for (int i=0; i<3; ++i) {
						if (announce_response_buffer[i] != 0) {
							announce_response_valid = 0;
						}	
					}
					if (announce_response_buffer[3] != 1) {
						announce_response_valid = 0;
					}
					for (int i=0; i<4; ++i) {
						if (announce_response_buffer[4+i] != transaction_id[i]) {
							announce_response_valid = 0;
						}
					}
					if (!announce_response_valid) {
						continue;
					}
					peer_list_obtained = 1;
					break;	
				}
				else if ((pfd.revents & (POLLERR + POLLHUP + POLLNVAL))>0) {
                                        printf("Error occurred whilst waiting for announce request bytes over udp during peer discovery via tracker.\n");
                                        return;
                                }
			 	int curr_bytes_read = recv(client_socket_fd, &(announce_response_buffer[bytes_read]), 300000 - bytes_read, 0);
				if (curr_bytes_read < 0) {
					printf("Error receiving bytes for tracker announce response. %s.\n", strerror(errno));
				        return;	
				}
				bytes_read += curr_bytes_read;
				if ((curr_bytes_read % peer_address_size)!=0) {
					while (((bytes_read - 20) % peer_address_size) != 0) {
						poll_res = poll(&pfd, 1, 3000);
						if (poll_res < 0) {
							printf("Error whilst receiving bytes from tracker announce responsee. %s.\n", strerror(errno));
							return;
						}
						else if (poll_res == 0) {
							continue;
						}	
						if ((pfd.revents & (POLLERR + POLLHUP + POLLNVAL))>0) {
                                		        printf("Error occurred whilst waiting for announce request bytes over udp during peer discovery via tracker.\n");
                		                        return;
		                                }
						int curr_bytes_read = recv(client_socket_fd, &(announce_response_buffer[bytes_read]), 300000 - bytes_read, 0);
                                		if (curr_bytes_read < 0) {
                                		        printf("Error receiving bytes for tracker announce response. %s.\n", strerror(errno));
                		                        return;
		                                }
						bytes_read += curr_bytes_read;
					}
				}
				if (ip_version == 4) {
					printf("Received and validated announce response packet from tracker %s\n", inet_ntoa(((struct sockaddr_in *)tracker_addr->ai_addr)->sin_addr));
				}
				else if (ip_version == 6) {
					uint8_t *trk_v6_addr = (((struct sockaddr_in6 *)tracker_addr->ai_addr)->sin6_addr).s6_addr;
					printf("Received and validated announce response packet from tracker %x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x..\n", trk_v6_addr[0], trk_v6_addr[1],
																	trk_v6_addr[2], trk_v6_addr[3],
																	trk_v6_addr[4], trk_v6_addr[5],
																	trk_v6_addr[6], trk_v6_addr[7],
																	trk_v6_addr[8], trk_v6_addr[9],
																	trk_v6_addr[10], trk_v6_addr[11],
																	trk_v6_addr[12], trk_v6_addr[13],
																	trk_v6_addr[14], trk_v6_addr[15]);
				}

				peer_list_obtained = 1;
				break;
			}
			if (secs_since_connect_id_receipt > 60.0) {
				continue;
			}			
		}	
		// peer list obtained	
		if (ip_version == 4) {
			printf("Peer list obtained from tracker %s containing %d peers.\n", inet_ntoa(((struct sockaddr_in *)tracker_addr->ai_addr)->sin_addr),
											    ((bytes_read - 20)/peer_address_size));
		}
		else if (ip_version == 6) {
			uint8_t *trk_v6_addr = (((struct sockaddr_in6 *)tracker_addr->ai_addr)->sin6_addr).s6_addr;
			printf("Peer list obtained from tracker %x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x containing %d peers.\n", trk_v6_addr[0], trk_v6_addr[1],
															trk_v6_addr[2], trk_v6_addr[3],
															trk_v6_addr[4], trk_v6_addr[5],
															trk_v6_addr[6], trk_v6_addr[7],
															trk_v6_addr[8], trk_v6_addr[9],
															trk_v6_addr[10], trk_v6_addr[11],
															trk_v6_addr[12], trk_v6_addr[13],
															trk_v6_addr[14], trk_v6_addr[15],
															((bytes_read - 20)/peer_address_size));
		}

		announce_response_buffer_len = bytes_read;
		if ( pthread_mutex_lock(peers_access_mutex) != 0) {
			printf("Error locking mutex for peers_tree access.\n");
			return;
		}
		uint8_t ip_addr_size = peer_address_size - 2;
		for (int i=0; i<((announce_response_buffer_len - 20)/peer_address_size); ++i) {
			struct peer curr_peer;
			curr_peer.peer_id = 0;
			curr_peer.ip_addr = (uint8_t *)malloc(ip_addr_size);
			if (curr_peer.ip_addr == NULL) {
				printf("Error allocating memory for peer ip address. %s.\n", strerror(errno));
				return;
			}
			memcpy(curr_peer.ip_addr, &(announce_response_buffer[20+(i*peer_address_size)]), ip_addr_size);
			curr_peer.port = 0;
			curr_peer.port = announce_response_buffer[20 + ip_addr_size + (i*peer_address_size)];
			curr_peer.port <<= 8;
			curr_peer.port += announce_response_buffer[24 + (i*peer_address_size) + 1];
			curr_peer.ip_version = ip_version;
			btree_insert(peers_tree, &curr_peer);				
		}
		if ( pthread_mutex_unlock(peers_access_mutex) != 0) {
			printf("Error unlocking mutex for peers_tree access release.\n");
			return;
		}
		return;
	}
}

void obtain_peers_from_tracker(struct tracker *curr_tracker, 
			       struct binary_tree *peers_tree,
		               pthread_mutex_t *peers_access_mutex,
			       uint8_t *info_dict_sha1_hash,
			       uint8_t *peer_id)
{
	char *tracker_scheme_udp = "udp";
	size_t udp_scheme_len = strlen(tracker_scheme_udp);
	if (curr_tracker->scheme != 0) {
		if (strncmp(curr_tracker->scheme, 
			    tracker_scheme_udp, 
			    udp_scheme_len)==0) {
			// tracker should be acccessed over UDP
			if (curr_tracker->port == 0) {
				return; // port number required to access 
					// tracker program on its machine
			}
			struct addrinfo hints;
			hints.ai_flags = 0;
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_protocol = 17;
			hints.ai_addrlen = 0;
			hints.ai_addr = NULL;
			hints.ai_canonname = NULL;
			hints.ai_next = NULL;
			char service[10];
			memset(service, 0, 10);
			sprintf(service, "%u", curr_tracker->port);
			printf("Attempting to get address info for tracker %s:%s\n", curr_tracker->url, service);
			struct addrinfo *tracker_addr_list = NULL;
			if ( getaddrinfo(curr_tracker->url, service, &hints,
				         &tracker_addr_list) != 0) {
				printf("Error obtaining address for tracker %s.\n", curr_tracker->url);
				return;
			}
			while (tracker_addr_list) {
				obtain_peer_list_from_tracker_host(
						tracker_addr_list,
						peers_tree,
						peers_access_mutex,
						info_dict_sha1_hash,
						peer_id);
				tracker_addr_list = tracker_addr_list->ai_next;
			}
		}
	}

}

void *peer_discovery(void *thread_data)
{
	struct peer_discovery_thread_data *ptd = (struct peer_discovery_thread_data *)thread_data;
	int NoOfTrackers = vector_get_size(ptd->trackers_vector);
	for (int i=0; i<NoOfTrackers; ++i) {
		struct tracker *curr_tracker = vector_read(ptd->trackers_vector,
				                           i);
		obtain_peers_from_tracker(curr_tracker, ptd->peers_tree,  ptd->access_peers_tree_mutex, ptd->info_dict_sha1_hash, ptd->peer_id);
	}
}
