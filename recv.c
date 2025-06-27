/*=============================;
 *
 * File: recv.c
 * Content: Implementation of thread
 * safe function to receive BitTorrent packets.
 * Date: 26/6/2025
 *
 **********************************/

#include "recv.h"

uint8_t *recv_packet(int client_socket_fd, int *bytes_rcvd, int ms_timeout,
		     pthread_mutex_t *recv_mutex,
		     pthread_mutex_t *poll_mutex,
		     pthread_mutex_t *mem_mutex)
{
	struct pollfd polld;
	polld.fd = client_socket_fd;
	polld.events = POLLIN;
	if (pthread_mutex_lock(poll_mutex) != 0) {
		printf("Error locking polling mutex.\n");
		exit(EXIT_FAILURE);
	}
	int poll_res = poll(&polld, 1, ms_timeout);
	if ( pthread_mutex_unlock(poll_mutex)!=0 ) {
		printf("Error unlocking poling mutex.\n");
		exit(EXIT_FAILURE);
	}
	int recv_data_len = 1000;
	if (pthread_mutex_lock(mem_mutex) != 0) {
		printf("Error locking memory mutex.\n");
		exit(EXIT_FAILURE);
	}
	uint8_t *recv_data = (uint8_t *)malloc(recv_data_len);
	if (pthread_mutex_unlock(mem_mutex) != 0) {
		printf("Error unlcoking memory mutex.\n");
		exit(EXIT_FAILURE);
	}
	if (recv_data == NULL) {
		printf("Error allocating memory for peer packet.%s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	int bytes_read = 0;
read_length_prefix:
	while (bytes_read != 4) {
		if (poll_res == 0) {
			printf("Timeout occurred when expecting packet.\n");
			if (pthread_mutex_lock(mem_mutex) != 0) {
				printf("Error locking memory mutex.\n");
				exit(EXIT_FAILURE);
			}
			free(recv_data); 
			if (pthread_mutex_unlock(mem_mutex) != 0) {
				printf("Error unlcoking memory mutex.\n");
				exit(EXIT_FAILURE);
			}
			*bytes_rcvd = 0;
			return 0;
		}
		else if (poll_res < 0) {
			printf("Error occurred whilst calling poll and waiting for peer date.%s\n",
				strerror(errno));
			if (pthread_mutex_lock(mem_mutex) != 0) {
                                printf("Error locking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
                        free(recv_data);
                        if (pthread_mutex_unlock(mem_mutex) != 0) {
                                printf("Error unlcoking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
			*bytes_rcvd = 0;
			return 0;
		}
		else if (polld.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			printf("Error occurred whilst calling poll and waiting for peer data.\n");
                        if (pthread_mutex_lock(mem_mutex) != 0) {
                                printf("Error locking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
                        free(recv_data);
                        if (pthread_mutex_unlock(mem_mutex) != 0) {
                                printf("Error unlcoking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
                        *bytes_rcvd = 0;
                        return 0;
		}
		else if (polld.revents & POLLIN) {
			//data to be read
			if (pthread_mutex_lock(recv_mutex) != 0) {
				printf("Error locking recv call mutex.\n");
				exit(EXIT_FAILURE);
			}
			int new_bytes_read = recv(client_socket_fd,
						  &(recv_data[bytes_read]),
						  4 - bytes_read,
						  0);
			if (pthread_mutex_unlock(recv_mutex) != 0) {
				printf("Error unlocking recv call mutex.\n");
				exit(EXIT_FAILURE);
			}
			if (new_bytes_read <= 0) {
				printf("Error occurred whilst receiving data from peer.\n");
				if (pthread_mutex_lock(mem_mutex) != 0) {
					printf("Error locking memory mutex.\n");
					exit(EXIT_FAILURE);
				}
				free(recv_data); 
				if (pthread_mutex_unlock(mem_mutex) != 0) {
					printf("Error unlcoking memory mutex.\n");
					exit(EXIT_FAILURE);
				}
				*bytes_rcvd = 0;
				return 0;
			}
			bytes_read += new_bytes_read;
			if (pthread_mutex_lock(poll_mutex) != 0) {
				printf("Error locking polling mutex.\n");
				exit(EXIT_FAILURE);
			}
			poll_res = poll(&polld, 1, ms_timeout);
			if ( pthread_mutex_unlock(poll_mutex)!=0 ) {
				printf("Error unlocking poling mutex.\n");
				exit(EXIT_FAILURE);
			}
		}
		else {
			printf("Error occurred whilst calling poll and waiting for peer data.\n");
                        if (pthread_mutex_lock(mem_mutex) != 0) {
                                printf("Error locking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
                        free(recv_data);
                        if (pthread_mutex_unlock(mem_mutex) != 0) {
                                printf("Error unlcoking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
                        *bytes_rcvd = 0;
                        return 0;
		}
	}

	uint32_t message_len = 4;
	message_len += ((recv_data[0] << 24) + (recv_data[1] << 16) + (recv_data[2] << 8) + (recv_data[3]));
	if (message_len == 4) {
		// keepalive present. skip this.
		bytes_read = 0;
		if (pthread_mutex_lock(mem_mutex) != 0) {
                	printf("Error locking memory mutex.\n");
        	        exit(EXIT_FAILURE);
	        }
		void * t = realloc(recv_data, recv_data_len);
		recv_data = t;
		if (pthread_mutex_unlock(mem_mutex) != 0) {
                	printf("Error locking memory mutex.\n");
        	        exit(EXIT_FAILURE);
	        }
		if (pthread_mutex_lock(poll_mutex) != 0) {
                	printf("Error locking polling mutex.\n");
                	exit(EXIT_FAILURE);
        	}
        	poll_res = poll(&polld, 1, ms_timeout);
        	if ( pthread_mutex_unlock(poll_mutex)!=0 ) {
                	printf("Error unlocking poling mutex.\n");
        	        exit(EXIT_FAILURE);
	        }
		goto read_length_prefix;
	}
	 if (pthread_mutex_lock(mem_mutex) != 0) {
                printf("Error locking memory mutex.\n");
                exit(EXIT_FAILURE);
        }
        uint8_t *temp = (uint8_t *)realloc(recv_data, message_len);
        if (pthread_mutex_unlock(mem_mutex) != 0) {
                printf("Error unlcoking memory mutex.\n");
                exit(EXIT_FAILURE);
        }
	if (temp == NULL) {
		printf("Error reallocating memory for packet received by peer.%s.\n",strerror(errno));
		exit(EXIT_FAILURE);
	}
	recv_data = temp;
 	while (bytes_read != message_len) {
		if (poll_res == 0) {
			printf("Timeout occurred when expecting packet.\n");
                        if (pthread_mutex_lock(mem_mutex) != 0) {
                                printf("Error locking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
                        free(recv_data);
                        if (pthread_mutex_unlock(mem_mutex) != 0) {
                                printf("Error unlcoking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
                        *bytes_rcvd = 0;
                        return 0;
		}
		else if ( poll_res == -1) {
			printf("Error occurred whilst calling poll and waiting for peer date.%s\n",
                                strerror(errno));
                        if (pthread_mutex_lock(mem_mutex) != 0) {
                                printf("Error locking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
                        free(recv_data);
                        if (pthread_mutex_unlock(mem_mutex) != 0) {
                                printf("Error unlcoking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
                        *bytes_rcvd = 0;
                        return 0;
		}
		else if (polld.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			printf("Error occurred whilst calling poll and waiting for peer data.\n");
                        if (pthread_mutex_lock(mem_mutex) != 0) {
                                printf("Error locking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
                        free(recv_data);
                        if (pthread_mutex_unlock(mem_mutex) != 0) {
                                printf("Error unlcoking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
                        *bytes_rcvd = 0;
                        return 0;
		}	
		else if (polld.revents & POLLIN) {
			//data ready to be read
			if (pthread_mutex_lock(recv_mutex) != 0) {
				printf("Error locking recv call mutex.\n");
				exit(EXIT_FAILURE);
			}
			int new_bytes_read = recv(client_socket_fd,
						  &(recv_data[bytes_read]),
						  message_len - bytes_read,
					          0);
	      		if (pthread_mutex_unlock(recv_mutex) != 0) {
				printf("Error unlocking recv call mutex.\n");
				exit(EXIT_FAILURE);
			}		
			if (new_bytes_read <= 0) {
				if (pthread_mutex_lock(mem_mutex) != 0) {
					printf("Error locking memory mutex.\n");
					exit(EXIT_FAILURE);
				}
				free(recv_data); 
				if (pthread_mutex_unlock(mem_mutex) != 0) {
					printf("Error unlcoking memory mutex.\n");
					exit(EXIT_FAILURE);
				}
				*bytes_rcvd = 0;
				return 0;
			}				
			bytes_read += new_bytes_read;
			if (pthread_mutex_lock(poll_mutex) != 0) {
				printf("Error locking polling mutex.\n");
				exit(EXIT_FAILURE);
			}
			poll_res = poll(&polld, 1, ms_timeout);
			if ( pthread_mutex_unlock(poll_mutex)!=0 ) {
				printf("Error unlocking poling mutex.\n");
				exit(EXIT_FAILURE);
			}
		}
		else {
			// an error occurred
			printf("Error occurred whilst calling poll and waiting for peer data.\n");
                        if (pthread_mutex_lock(mem_mutex) != 0) {
                                printf("Error locking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
                        free(recv_data);
                        if (pthread_mutex_unlock(mem_mutex) != 0) {
                                printf("Error unlcoking memory mutex.\n");
                                exit(EXIT_FAILURE);
                        }
                        *bytes_rcvd = 0;
                        return 0;
		}

	}
	*bytes_rcvd = message_len;
	return recv_data;
}
