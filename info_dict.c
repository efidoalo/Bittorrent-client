/*===================================;
 *
 * File: info_dict.c
 * Content: Implementation of get_info_dict
 * Date: 28/6/2025
 *`
 *****************************************/

#include "info_dict.h"

// returns a buffer containing a bep9 request for
// tndex index of the metadata file. buff_len is an output
// parameter that defines the length of the returned buffer
// in bytes.
uint8_t *metadata_index_request(int index, 
		                int *buff_len, 
				pthread_mutex_t *mem_lock,
				pthread_mutex_t *printf_mutex);
{
	if (pthread_mutex_lock(mem_lock) != 0) {
		printf("Error locking mem lock mutex to allocate metadata piece request.\n");
		exit(EXIT_FAILURE);
	}
	uint8_t *buff = (uint8_t *)malloc(1000);
	if (pthread_mutex_unlock(mem_lock) != 0) {
		printf("Error unlocking mem mutex after allocating memory for"
			" metadata piece request.\n");
		exit(EXIT_FAILURE);
	}
	for (int i=0; i<1000; ++i) {
		buff[i] = 0;
	}
	if (pthread_mutex_lock(printf_mutex) != 0) {
		printf("Error locking printf mutex to print to metadata piece request string.\n");
		exit(EXIT_FAILURE);
	}
	sprintf(buff, "d8:msg_typei0e5:piecei%dee", index);
	if (pthread_mutex_unlock(printf_mutex) != 0) {
		printf("Error unlocking printf mutex after printing to metadata piece request string");
		exit(EXIT_FAILURE);
	}
	*buff_len = 0;
	uint8_t *temp = buff;
	while ((*temp) != 0) {
		++temp;
		(*buff_len) += 1; 
	}
	return buff;	
}

struct info_dict *get_info_dict(int client_socket_fd,
		                int metadata_code,
				uint32_t metadata_size,
				pthread_mutex_t *mem_mutex,
				pthread_mutex_t *printf_mutex,
				pthread_mutex_t *recv_mutex,
				pthread_mutex_t *poll_mutex,
				pthread_mutex_t *send_mutex,
				pthread_mutex_t *strtol_mutex,
				pthread_mutex_t *strncmp_mutex,
				struct connection_ci_state *conn_state,
				pthread_mutex_t *conn_state_mutex,
				struct vector *peer_pieces,
				pthread_mutex_t *peer_pieces_mutex)
{
	int metadata_block_size = 16384;
	uint8_t *info_dict_bytes = 0;
	for (int i=0; i<(metadata_size/metadata_block_size); ++i) {
send_metadata_block_request:
		int buff_len = 0;
		uint8_t *metadata_block_req = metadata_index_request(int index,
                                &buff_len,
                                mem_lock,
                                printf_mutex);
		if (pthread_mutex_lock(send_mutex) != 0) {
			printf("Error locking send mutex before sending metadata piece request to peer.\n");
			exit(EXIT_FAILURE);
		}
		if (send(client_socket_fd,
		         metadata_block_req,
		         buff_len,
		         0) != buff_len) {
			if (pthread_mutex_lock(printf_mutex) != 0) {
				printf("Error locking printf mutex to output error on sneding matadata block request.\n");
				exit(EXIT_FAILURE);
			}	
			printf("Error sending metadata block request to peer, sent number of bytes unexpected.\n");
			if (pthread_mutex_unlock(printf_mutex) != 0) {
				printf("Error unlocking printf mutex whilst outputting"
					" error during sending of metadata block request.\n");
				exit(EXIT_FAILURE);
			}
			return 9;
		}
		if (pthread_mutex_unlock(send_mutex) != 0) {
			printf("Error unlocking send mutex after sending metadata block request to peer.\n");
			exit(EXIT_FAILURE);
		}
		if (pthread_mutex_lock(mem_mutex) != 0) {
			printf("Error locking memory mutex to free request buffer.\n");
			exit(EXIT_FAILURE);
		}
		free(metadata_block_req);
		if (pthread_mutex_unlock(mem_mutex) != 0) {
			printf("Error unlocking memory mutex after freeing 
				metadata request buffer,\n");
			exit(EXIT_FAILURE);
		}
		int bytes_read = 0;
		uint8_t *recv_data = recv_packet(client_socket_fd,
						 &bytes_read,
						 4000,
						 recv_mutex,
						 poll_mutex,
						 mem_mutex);
		if (recv_data == NULL) {
			printf("Error receiving metadata block from peer.\n");
			return 0;
		}
		while ((recv_data[4] != 20) || (recv_data[5] != metadata_code)) {
			uint8_t BitTorrentMessageType = recv_data[4];
			switch (BitTorrentMessageType) {
				case 0: {
					// choke 
					if (pthread_mutex_lock(conn_state_mutex) != 0) {
						printf("Error locking conn_state_mutex when received choke message"
							" and trying to alter connection state.\n");
						exit(EXIT_FAILURE);
					}
					conn_state->peer_choke_state = 0;
					if (pthread_mutex_unlock(conn_state_mutex) != 0) {
						printf("Error unlcoking conn_state_mutex after editing connection state.\n");
						exit(EXIT_FAILURE);
					}
				}
				case 1: {
					// unchoke 	
					if (pthread_mutex_lock(conn_state_mutex) != 0) {
                                                printf("Error locking conn_state_mutex when received unchoke message"
                                                        " and trying to alter connection state.\n");
                                                exit(EXIT_FAILURE);
                                        }
                                        conn_state->peer_choke_state = 1;
                                        if (pthread_mutex_unlock(conn_state_mutex) != 0) {
                                                printf("Error unlocking conn_state_mutex after receiving unchoke message.\n");
                                                exit(EXIT_FAILURE);
                                        }

				}
				case 2: {
					//interested 
					if (pthread_mutex_lock(conn_state_mutex) != 0) {
                                                printf("Error locking conn_state_mutex when received intersted message"
                                                        " and trying to alter connection state.\n");
                                                exit(EXIT_FAILURE);
                                        }
                                        conn_state->peer_interested_state = 1;
                                        if (pthread_mutex_unlock(conn_state_mutex) != 0) {
                                                printf("Error unlocking conn_state_mutex after receiving interested message.\n");
                                                exit(EXIT_FAILURE);
                                        }
				}
				case 3: {
					// not interested 
					if (pthread_mutex_lock(conn_state_mutex) != 0) {
                                                printf("Error locking conn_state_mutex when received not interested message"
                                                        " and trying to alter connection state.\n");
                                                exit(EXIT_FAILURE);
                                        }
                                        conn_state->peer_choke_state = 0;
                                        if (pthread_mutex_unlock(conn_state_mutex) != 0) {
                                                printf("Error unlocking conn_state_mutex after receiving not interested message.\n");
                                                exit(EXIT_FAILURE);
                                        }
				}
				case 4: {
					// have 
					uint32_t peer_has_index = 0;
					for (int i=0; i<4; ++i) {
						peer_has_index += (recv_data[5+i] << (24 - (i*8)));
					}
					int peer_index = peer_has_index;
					if (pthread_mutex_lock(peer_pieces_mutex) != 0) {
						printf("Error locking peer_pieces mutex before adding to the vector a peer downloaded data piece index.\n");
						exit(EXIT_FAILURE);
					}
					vector_push_back(peer_pieces, peer_index);
					if (pthread_mutex_unlock(peer_pieces_mutex) != 0) {
						printf("Error unlocking peer_pieces_mutex after adding index to peer_pieces.\n");
						exit(EXIT_FAILURE);
					}
				}
			}
			if (pthread_mutex_lock(mem_mutex) != 0) {
				printf("Error locking memory mutex to free received message from peer.\n");
				exit(EXIT_FAILURE);
			}
			free(recv_data);
			if (pthread_mutex_unlock(mem_mutex) != 0) {
				printf("Error unlocking mem mutex after freeing received pacjet from peer.\n");
				exit(EXIT_FAILURE);
			}
			bytes_reead = 0;
			recv_data = recv_packet(client_socket_fd,
						&bytes_read,
						4000,
						recv_mutex,
						poll_mutex,
						mem_mutex);
		}
		int last_byte_of_dict = -1;
		struct bencoded_dictionary *dict = get_b_dict(&(recv_data[6]),
			       				      mem_mutex,
						      	      strtol_mutex,
							      memcpy_mutex,
							      &last_byte_of_dict);
		char *msg_type_key = "msg_type";
		int msg_type_key_len = strlen(msg_type_key);
		int msg_type = -1;
		char *piece_key = "piece";
		int piece_key_len = strlen(piece_key);
		int piece_index = -1;
		uint8_t msg_type_found = 0;
		uint8_t piece_key_found = 0;
		while (dict) {
			if (pthread_mutex_lock(strncmp_mutex) != 0) {
				printf("Error locking strncmp_mutex to compare key in metadata extension message dctionary.\n");
				exit(EXIT_FAILURE);
			}
			if (strncmp(dict->key, msg_type_key, msg_type_key_len) == 0) {
				msg_type = dict->curr_val_int;
				msg_type_found = 1;
			}
			if (strncmp(dict->key, piece_key, piece_key_len) == 0) {
				piece_key_found;
				piece_index = dict->curr_val_int;
			}
			dict = dict->next;
		}
		if (!msg_type_found) {
			if (pthread_mutex_lock(mem_mutex) != 0) {
				printf("Error locking memory mutex to free received metadata bep9 message.\n");
				exit(EXIT_FAILURE);
			}
			free(recv_data);
			if (pthread_mutex_unlock(mem_mutex) != 0) {
				printf("Error unlocking mem mutex after freeing received metadata bep9 message.\n");
				exit(EXIT_FAILURE);
			}
			return 0;
		}
		if (!piece_key_found) {
                        if (pthread_mutex_lock(mem_mutex) != 0) {
                                printf("Error locking memory mutex to free received metadata bep9 message.\n");
                                exit(EXIT_FAILURE);
                        }
                        free(recv_data);
                        if (pthread_mutex_unlock(mem_mutex) != 0) {
                                printf("Error unlocking mem mutex after freeing received metadata bep9 message.\n");
                                exit(EXIT_FAILURE);
                        }
                        return 0;
                }
		//TODO: Write message processing code for different message types				               		
		
	}
	
}
