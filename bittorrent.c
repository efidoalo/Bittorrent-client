/*===================================;
 *
 * File: bittorrent.c
 * Contetnt: A bittorrent cli client
 * program
 * Date: 27/05/2021
 * Note: Execute via ./bittorrent {magnet link} 
 *
 ************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <byteswap.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <endian.h>
#include <signal.h>
#include "vector.h"
#include "doubly_linked_list.h"
#include "binary_tree.h"

// ml is a null terminated string specifies magnet link.
// This function returns the 1 if the magnet is of format
// v1: magnet:?xt=urn:btih.....
// and returns 2 if the magnet link is of format
// v2: magnet:?xt=urn:btmh.....
// If ml doestn'tmatch either of these formats then 0 is returned.
unsigned char magnet_link_version(char *ml)
{
	const char *v1_ml = "magnet:?xt=urn:btih:";
	const char *v2_ml = "magnet:?xt=urn:btmh:";
 	unsigned int str_len = strlen(v1_ml);
	if (strncmp(ml, v1_ml, str_len)==0) {
		return 1;
	}
	else if (strncmp(ml, v2_ml, str_len)==0) {
		return 2;
	}
	else {
		return 0;
	}
}

struct tracker_endpoint
{
        char *url;
        unsigned short udp_port;
};

// This function assumes ml points to the part of the magnet link that
// is the start of a tracker url (percent encoded of the form scheme://host:port
// , where scheme, host and port do not include any percent encoded characters).
// ascii_url is a pre-allocated buffer that is guaranteed to be of sufficient 
// length to hold the null terminated tracker url string. 
// This function converts the url pointed to by  ml 
// (which has escaped characters) to ascii_url which is a pure ascii url 
// (no escaped characters).
// Returns 1 on success, 0 on failure.
int obtain_tracker_url(char *ml, char *ascii_url)
{
	char colon0[2] = {'3','a'};
	char colon1[2] = {'3','A'};
	char forward_slash0[2] = {'2','f'};
	char forward_slash1[2] = {'2','F'};
	int ml_index = 0, ascii_url_index = 0;
	// get scheme
	while (ml[ml_index] != '%') {
		++ml_index;
	}
	++ml_index; // skip '%'
	if (strncmp(&(ml[ml_index]), colon0, 2)==0) {
		ml_index += 2;
	}
	else if (strncmp(&(ml[ml_index]), colon1, 2)==0) {
		ml_index += 2;
	}
	else {
		return 0;
	}
	++ml_index; // skip '%'
	if (strncmp(&(ml[ml_index]), forward_slash0, 2)==0) {
		ml_index += 2;
	}
	else if (strncmp(&(ml[ml_index]), forward_slash1, 2)==0) {
                ml_index += 2;
	}
	else {
		return 0;
	}
	++ml_index; // skip '%'
	if (strncmp(&(ml[ml_index]), forward_slash0, 2)==0) {
                ml_index += 2;
        }
        else if (strncmp(&(ml[ml_index]), forward_slash1, 2)==0) {
                ml_index += 2;
        }
	else {
		return 0;
	}
	while (ml[ml_index]!='%') { // read up to port number
		ascii_url[ascii_url_index++] = ml[ml_index++];
	}
	ascii_url[ascii_url_index] = 0;
	return 1;
}

// ml gives the address in a string that defines the start of a tracker
// endpoint url. The ml string should be considered len bytes long
// (excluding null terminator/additional data). This function returns a port
// number for the tracker given in ml.
unsigned short obtain_tracker_port(char *ml, int len)
{
	int colon_count = 0;
	char colon0[3] = {'%','3','a'};
        char colon1[3] = {'%','3','A'};
	int index = 0;
	while (index <= (len-3)) {
		if ( (strncmp(&(ml[index]), colon0, 3)==0) || 
	             (strncmp(&(ml[index]), colon1, 3)==0) ) { 
			++colon_count;
			if (colon_count == 2) {
				index += 3;
				unsigned short port_no = atoi(&(ml[index]));
				return port_no;
			}
			index += 3;
		}
		else {
			++index;
		}
	}
 	return 0; // ml provided an unsupported url format, we return the reserved port number 0	
}

// ml is a magnet link (version 1 type) and this function returns
// a pointer to a vector of tracker_endpoints, where each tracker
// endpoint defines a url and a udp port number for a tracker. 
struct vector *get_trackers(char *ml)
{
	struct vector *trackers = vector_null_init(sizeof(struct tracker_endpoint));
	char *info_present = "&tr="; 
	int curr_pos = 0;
	int ml_str_len = strlen(ml);
	while (curr_pos < ml_str_len) {
		if (strncmp(&(ml[curr_pos]), info_present, 4)==0) {
			curr_pos += 4;
			int curr_tracker_info_index = 0;
			unsigned char last_tracker_in_list = 0;
			while (  ((curr_pos + curr_tracker_info_index+3)<ml_str_len) 
			         && (strncmp(&(ml[curr_pos + curr_tracker_info_index]) ,info_present, 4) != 0) ) {
				++curr_tracker_info_index;
			}
			if ((curr_pos + curr_tracker_info_index+3)>=ml_str_len) {
				// last tracker info in ml
				char *tracker_url = (char *)malloc(ml_str_len-curr_pos);
				if (obtain_tracker_url(&(ml[curr_pos]), tracker_url)==0) {
					free(tracker_url);
					return trackers;
				}
				unsigned short tracker_udp_port = obtain_tracker_port(&(ml[curr_pos]), ml_str_len - curr_pos);
				struct tracker_endpoint te = {tracker_url, tracker_udp_port};
				vector_push_back(trackers, &te);
				return trackers;
			}
			else {
				char *tracker_url = (char *)malloc(curr_tracker_info_index+1);
				if (obtain_tracker_url(&(ml[curr_pos]), tracker_url)==0) {
					curr_pos += curr_tracker_info_index;
					free(tracker_url);
					continue;
				}
				unsigned short tracker_udp_port = obtain_tracker_port(&(ml[curr_pos]), curr_tracker_info_index);
				struct tracker_endpoint te = {tracker_url, tracker_udp_port};
				vector_push_back(trackers, &te);
				curr_pos += curr_tracker_info_index;
				continue;
			}
				       
		}
		else {
			++curr_pos;
		}
	}	
	return trackers;
}

// Extract the info hash included in the magnet link and place
// it into the 20 byte buffer at address info_hash
void extract_info_hash(unsigned char *magnet_link, unsigned char *info_hash)
{
	int index = 20;
	for (int i=0; i<20; ++i) {
		unsigned char curr_byte = 0;
		if (magnet_link[index+(i*2)]<58) {
			curr_byte += (magnet_link[index + (i*2)]-48)*16;
		}	
		else if (magnet_link[index+(i*2)]<71) {
			curr_byte += (magnet_link[index + (i*2)]-55)*16;
		}
		else {
			curr_byte += (magnet_link[index +(i*2)]-87)*16;
		}
		if (magnet_link[index +(i*2)+1]<58) {
			curr_byte += (magnet_link[index + (i*2)+1]-48);
		}
		else if (magnet_link[index + (i*2)+1]<71) {
			curr_byte += (magnet_link[index + (i*2)+1]-55);
		}
		else {
			curr_byte += (magnet_link[index+(i*2)+1]-87);
		}
		info_hash[i] = curr_byte;
	}
}

// Insert a random number into the 20 byte peer_id
void insert_random_peer_id(unsigned char *peer_id)
{
	for (int i=0; i<20; ++i) {
		peer_id[i] = rand() % 256;
	}
}

struct tracker_conn_request
{
	unsigned char protocol_id[8];
	unsigned int action;
	unsigned int transaction_id;	
};

struct tracker_conn_response
{
	unsigned int action;
	unsigned int transaction_id;
	unsigned char connection_id[8];
};

struct  __attribute__((__packed__)) tracker_announce_request
{
	unsigned char connection_id[8];
	unsigned int action;
	unsigned int transaction_id;
	unsigned char info_hash[20];
	unsigned char peer_id[20];
	unsigned char downloaded[8];
	unsigned char left[8];
	unsigned char uploaded[8];
	unsigned int event;
	unsigned int ip_addr;
	unsigned int key;
	int num_want;
	unsigned short int port;	
};

// returns 15 * 2^n, where n is an integer >= 0
int get_timeout(int n)
{
	if (n<1) {
		return 15; // handles negative values as well as 0.
	}
	return (int)(15*pow(2, n));
}

struct obtain_peer_list_data
{
	struct tracker_endpoint *te;
	unsigned char peer_list[6020];
	unsigned char peer_id[20];
	unsigned int list_len;
	char *magnet_link;
	unsigned int *max_list_len;
	pthread_mutex_t *max_list_len_mutex;
};

unsigned char magic_constant[8] = {0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80};

struct __attribute__((__packed__)) bittorrent_main_handshake {
	unsigned char len_19_prefix;
	unsigned char bittorrent_protocol[19];
	unsigned char reserved_bytes[8];
	unsigned char sha1_info_hash[20];
	unsigned char peer_id[20];
};

void *obtain_peer_list_from_tracker(void *tracker_metadata)
{
	struct obtain_peer_list_data *tm = (struct obtain_peer_list_data *)tracker_metadata;

	int client_socket_fd = socket(AF_INET, SOCK_DGRAM, 17); //UDP
        if (client_socket_fd == -1) {
                printf("Error creating client endpoint.\n");
        }
	struct tracker_conn_request tcrequest;
        memcpy(tcrequest.protocol_id, magic_constant, 8);
        tcrequest.action = 0;

        struct addrinfo tracker_addr_hint;
        tracker_addr_hint.ai_flags = 0;
        tracker_addr_hint.ai_family = AF_INET;
        tracker_addr_hint.ai_socktype = SOCK_DGRAM;
        tracker_addr_hint.ai_protocol = 17;
        tracker_addr_hint.ai_addrlen = 0;
        tracker_addr_hint.ai_addr = NULL;
        tracker_addr_hint.ai_canonname = NULL;
        tracker_addr_hint.ai_next = NULL;

        unsigned char *peer_list = tm->peer_list; // Memory to hold a maximum of 1000 peers (ipv4 address and tcp port number of each peer)
        unsigned char peer_list_obtained = 0; // set to 1 when we have obtained a peer list

	struct tracker_endpoint *curr_tracker = tm->te;

	struct addrinfo *tracker_addr_info = 0;
        char tracker_port[6] = {0};
        sprintf(tracker_port, "%u", curr_tracker->udp_port);
        printf("Attempting to get peer info from tracker %s:%s.\n",curr_tracker->url, tracker_port);
        int res = getaddrinfo(curr_tracker->url, tracker_port, &tracker_addr_hint,
                                      &tracker_addr_info);
        if (res!=0) {
        	printf("Error occurred getting tracker address info. %s\n",gai_strerror(errno));
                return 0;
        }
        if (tracker_addr_info == 0) {
                printf("No tracker address info retrieved by getaddrinfo.\n");
                return 0;
        }
	while (tracker_addr_info) {
                int n = 0;
                struct timeval tv;
                fd_set read_fds;
                tcrequest.transaction_id = rand() + rand();

                while (n<=8) {     
                	tv.tv_sec = get_timeout(n);
        	        tv.tv_usec = 0;
                        int no_of_sent_bytes = sendto(client_socket_fd,
                                                      &tcrequest,
                                                      sizeof(struct tracker_conn_request),
                                                      0,
                                                      tracker_addr_info->ai_addr,
                                                      (socklen_t)sizeof(struct sockaddr));
                        FD_ZERO(&read_fds);
                        FD_SET(client_socket_fd, &read_fds);
                        int res = select(client_socket_fd+1, &read_fds, NULL, NULL, &tv);
                        if (res == -1) {
                        	struct sockaddr_in *tracker_addr = (struct sockaddr_in *)(tracker_addr_info->ai_addr);
                                printf("Error calling select() to wait (with a timeout) for connect response to arrive at socket"
                                               " that was sent from tracker %s.\n", inet_ntoa(tracker_addr->sin_addr));
                                ++n;
                                continue;
                        }
                        else if (res == 0) {
                                        // timeout occurred
                                printf("Timeout occurred after %d seconds.\n", get_timeout(n));
                                ++n;
				continue;
                        }
                        else if (res > 0) {
                                // data ready to read (connect response)
                                unsigned char conn_response[100] = {0};
                                struct sockaddr_in src_addr;
                                struct sockaddr_in *tracker_addr = (struct sockaddr_in *)tracker_addr_info->ai_addr;
                                socklen_t addr_len = sizeof(struct sockaddr_in);
			        int bytes_recv = 0;
                                int resend_conn_request = 0;
                                while (bytes_recv < 16) {
                                	addr_len = sizeof(struct sockaddr_in);
                                        int new_bytes = recvfrom(client_socket_fd, &(conn_response[bytes_recv]), 100-bytes_recv, 0,
                                	                         (struct sockaddr *)&src_addr, &addr_len);
                                        if (strncmp((const char *)&src_addr, (const char *)tracker_addr,
                                                    sizeof(struct sockaddr_in))==0) {
                                        	bytes_recv += new_bytes;
                                        }
                                        if (bytes_recv < 16) {
						FD_ZERO(&read_fds);
						FD_SET(client_socket_fd, &read_fds);
						int wait_res = select(client_socket_fd+1, &read_fds, NULL, NULL, &tv);
						if (wait_res == 0) {
				 			// timeout occurred
			 				resend_conn_request = 1;
		 					++n;
	 						break;
 						}
 						else if (wait_res == -1) {
	 						// error occurred
  							resend_conn_request = 1;
							++n;
							break;
						}
					}
				}
				if (resend_conn_request) {
					continue;
				}
				struct tracker_conn_response *tcresponse = (struct tracker_conn_response *)conn_response;
				if (tcrequest.transaction_id != (tcresponse->transaction_id)) {
					printf("transaction_id received from tracker not matched to sent transaction_id.\n");
					++n;
					continue;
				}
			  	time_t connection_id_recv = time(NULL);
		  		//printf("here: %u\n", sizeof(struct tracker_announce_request));
	   			struct tracker_announce_request tarequest;
				memset(&tarequest, 0, sizeof(struct tracker_announce_request));
    				memcpy(tarequest.connection_id, tcresponse->connection_id, 8);
				tarequest.action = htonl(1);
				tarequest.transaction_id = rand();
				extract_info_hash(tm->magnet_link, tarequest.info_hash);
				insert_random_peer_id(tarequest.peer_id);
				memcpy(tm->peer_id, tarequest.peer_id, 20); // save peer id for later
				memset(tarequest.downloaded, 0 ,8); // Downloaded set to zero
				tarequest.event = 0;
				tarequest.ip_addr = 0;
				memset(&tarequest.num_want, 255, 4);
				struct sockaddr_in client_socket_addr;
				socklen_t socklen = sizeof(struct sockaddr_in);
				int client_info_res = getsockname(client_socket_fd,
									(struct sockaddr *)&client_socket_addr,
									&socklen);
				if (client_info_res == -1) {
					printf("Error occurred when getting client socket info. Program terminating.\n");
					return 0;
				}
				tarequest.port = client_socket_addr.sin_port;
				time_t curr_time = time(NULL);
				while ((difftime(connection_id_recv, curr_time) < 60.0) && (n<=8)) {
					no_of_sent_bytes = sendto(client_socket_fd,
                                                                          &tarequest,
                                                                          sizeof(struct tracker_announce_request),
                                                                          0,
                                                                          tracker_addr_info->ai_addr,
                                                                          (socklen_t)sizeof(struct sockaddr));
					FD_ZERO(&read_fds);
					FD_SET(client_socket_fd, &read_fds);
					++n;
					tv.tv_sec = get_timeout(n);
					tv.tv_usec = 0;
					res = select(client_socket_fd+1, &read_fds, NULL, NULL, &tv);
					if (res == 0) {
					       	printf("Timeout occurred (after %d secs)  after sending tracker announce "
							"request.\n", get_timeout(n));
						++n;
						curr_time = time(NULL);
						continue;
					}
					else if (res == -1) {
						printf("Error occurred whilst waiting for tracker announce response.");
						++n;
						curr_time = time(NULL);
						continue;
					}
					else if (res > 0) {
						// data ready to be read (tracker announce response)
						bytes_recv = 0;
						int resend_ann_request = 0;
						while (bytes_recv < 20) {
							addr_len = sizeof(struct sockaddr_in);
							memset(&src_addr, 0, sizeof(struct sockaddr_in));
							int new_bytes = recvfrom(client_socket_fd,
										&(peer_list[bytes_recv]), 6020-bytes_recv, 0,
										(struct sockaddr *)&src_addr, &addr_len);
							if (strncmp((const char *)&src_addr, (const char *)tracker_addr,
									sizeof(struct sockaddr_in))==0) {
								bytes_recv += new_bytes;
							}
							if (bytes_recv < 20) {
								FD_ZERO(&read_fds);
								FD_SET(client_socket_fd, &read_fds);
								int wait_res = select(client_socket_fd+1, &read_fds, NULL, NULL, &tv);
								if (wait_res == 0) {
									// timeout occurred
									resend_ann_request = 1;
									++n;
									break;
								}
								else if (wait_res == -1) {
									// error occurred
									resend_ann_request = 1;
									++n;
									break;
								}
							}
						}
						if (resend_ann_request) {
							curr_time = time(NULL);
							continue;
						}
						if (bytes_recv > 20) {
							tm->list_len = (bytes_recv - 20)/6;
						}
						peer_list_obtained = 1;
						pthread_mutex_lock(tm->max_list_len_mutex);
						if ((tm->list_len) > (*(tm->max_list_len))) {
							*(tm->max_list_len) = tm->list_len;
						}
						pthread_mutex_unlock(tm->max_list_len_mutex);
						break;
					}
				}
				if (peer_list_obtained) {
					break;
				}
				if (n>8) {
					break;
				}
				else if (difftime(connection_id_recv, curr_time) >= 60.0) {
					tcrequest.transaction_id = rand() + rand();
					continue;
				}
			}
		}
		if (peer_list_obtained == 1) {
			break;
		}
		tracker_addr_info = tracker_addr_info->ai_next;
	}
	printf("max_list_len:%u\n", *(tm->max_list_len));
	return 0;
}

// This function obtains the index in the array of obtain_peer_list_data structures
// (of length NoOfTrackers) that corresponds to the tracker that provided the largest
// peer list
int get_max_peer_list_index(struct obtain_peer_list_data *pl_metadata, int NoOfTrackers)
{
	unsigned int max_len = 0;
 	int index = 0;
	for (int i=0; i<NoOfTrackers; ++i) {
		if ( (pl_metadata[i]).list_len > max_len) {
			max_len = (pl_metadata[i]).list_len;
			index = i;
		}
	}	
	return index;
}

struct request
{
        unsigned int piece_index;
        unsigned int begin;
        unsigned int length;
};

void *compare_requests(void *request1, void *request2)
{
	struct request *r1 = (struct request *)request1;
	struct request *r2 = (struct request *)request2;
	if ((r1->piece_index) < (r2->piece_index)) {
		return r2;
	}
	else if ((r1->piece_index) > (r2->piece_index)) {
		return r1;
	}
	else if ((r1->begin) < (r2->begin)) {
		return r2;
	}
	else if ((r1->begin) > (r2->begin)) {
		return r1;
	}
	else if ((r1->length) < (r2->length)) {
		return r2;
	}
	else if ((r1->length) > (r2->length)) {
		return r1;
	}
	return 0;
}

struct request_timestamp
{
	struct request request; // the request the client asked for
	time_t timestamp;       // the time when the request was sent
};

// function that compares request_timestamps by comparing
void *compare_rt(void *rt1, void *rt2)
{
	struct request_timestamp *req_time1 = (struct request_timestamp *)rt1;
	struct request_timestamp *req_time2 = (struct request_timestamp *)rt2;
	if ((req_time1->request).piece_index < (req_time2->request).piece_index) {
		return rt2;
	}
	else if ((req_time1->request).piece_index > (req_time2->request).piece_index) {
		return rt1;
	}
	else if ((req_time1->request).begin < (req_time2->request).begin) {
		return rt2;
	}
	else if ( (req_time1->request).begin > (req_time2->request).begin) {
		return rt1;
	}
	else if ( (req_time1->request).length < (req_time2->request).length) {
		return rt2;
	}
	else if ( (req_time1->request).length > (req_time2->request).length) {
		return rt1;
	}
	else {
		return 0;
	}
}

// function for printing request_timestamps
void print_rt(void *rt)
{
	struct request_timestamp *req_ts = (struct request_timestamp *)rt;
	printf("Requested piece index:%u\n"
               "Requested begin:%u\n"
	       "Requesten length:%u. Inspect struct to find timestamp of request.\n",
	       (req_ts->request).piece_index,
	       (req_ts->request).begin,
	       (req_ts->request).length);
}

struct client_per_peer_state
{
        unsigned char client_to_peer_choke_status; // 0 if client to peer data transfer is unchoked
                                                   // 1 if client to peer data transfer is choked
        unsigned char peer_interested; // 0 if peer is not interested in receiving any data
                                       // 1 if peer is interested in receiving data
        unsigned char peer_to_client_choke_status;  // 0 if peer to client data transfer is unchoked
                                                    // 1 if peer to client data transfer is choked
        unsigned char client_interested; // 0 if client is not interested in receiving data from peer
                                         // 1 if client is interested in receiving data from peer
        unsigned char *bitfield; // An array of bytes indicating which pieces the peer has already downloaded
                                 // This array is updated as have messages are received from the peer
	unsigned int bitfield_length; // the length of the bitfield array in bytes, this may dynamically change as have messages come in
	
        struct doubly_linked_list *requests; // requests sent from the peer received by the client. FIFO queue
	struct binary_tree *request_times; // keeps track of the times requests were sent from the client to the peer
					   // this is used to calculate per peer data download rates
	struct vector *download_rates;  // vector of unsigned integers giving the download rates in bytes per second
	pthread_mutex_t *download_rates_mutex;
	unsigned int previous_download_rate;
};

struct file
{
        unsigned long int length; // the length of the file in bytes
        char *path; // The path of the file, relative to the directory name
                    // containing all of the downloaded files. The last name in the
                    // path is the actual name of this file.
};

void print_file(void *f)
{
	struct file *curr_file = (struct file *)f;
	printf("length of file:%lu path:%s", curr_file->length, curr_file->path);
}

struct metadata_file_info_dict
{
        char *name; // the suggested name of the downloaded file
                    // or it's directory (if downloading multiple files)
        unsigned int piece_length; // The length in bytes of each piece of the file
        unsigned char *pieces; // an array of pieces_length bytes (which is a multiple of 20)
                               // whereby the ith string of length 20 is the sha1 hash of
                               // the ith piece of the file
        unsigned int pieces_length; // length of pieces array. Must be a multiple of 20
        unsigned long int length; // Only non zero if we are downloading a single
                                  // file, in which case length is the size in
                                  // bytes of the full file.
        struct doubly_linked_list *files; // A doubly linked list of files
                                          // in the order they appear in the
                                          // download. this pointer is non zero
                                          // only if we are downloading multiple
                                          // files. this list stores struct file 's
};

struct obtain_metadata_info_per_thread_data
{
	char *magnet_link;
	struct sockaddr_in peer;
	int client_socket_fd;
	unsigned char peer_id[20];
	unsigned char **metadata_info_dictionary;
	pthread_mutex_t *metadata_info_dict_mutex; // used for accessing and modifying the metadata_info_dict pointer
	unsigned char *obtained_metadata_info_dict;
	struct metadata_file_info_dict **mi_data;
	pthread_mutex_t *mi_data_mutex;
	unsigned char *metadata_obtained;
};


// Function returns 0 if bmh_peer is a valid bittorrent main handshake message (from the peer) with reserved_bytes[5]=0x10 
// to support the extension protocol bep 10. sha1_info_hash is the sha1 hash given in the magnet link in byte form.
// Otherwise if bmh_peer is not valid the function returns 1
unsigned char check_peer_handshake(unsigned char *sha1_info_hash, struct bittorrent_main_handshake *bmh_peer)
{
	if (bmh_peer->len_19_prefix != 19) {
		return 1;
	}
	char *bittorrent_protocol_str = "BitTorrent protocol";
	for (int i=0; i<19; ++i) {
		if (bittorrent_protocol_str[i] != (bmh_peer->bittorrent_protocol)[i]) {
			return 1;
		}
	}
	if (((bmh_peer->reserved_bytes)[5] & 0x10)!= 0x10) {
		return 1;
	}
	for (int i=0; i<20; ++i) {
		if (sha1_info_hash[i] != ((bmh_peer->sha1_info_hash)[i])) {
			return 1;
		}
	}
	return 0;
}	

// checks handshake without any reserved byte checking in the header
unsigned char check_peer_handshake2(unsigned char *sha1_info_hash, struct bittorrent_main_handshake *bmh_peer)
{
        if (bmh_peer->len_19_prefix != 19) {
                return 1;
        }
        char *bittorrent_protocol_str = "BitTorrent protocol";
        for (int i=0; i<19; ++i) {
                if (bittorrent_protocol_str[i] != (bmh_peer->bittorrent_protocol)[i]) {
                        return 1;
                }
        }
        for (int i=0; i<20; ++i) {
                if (sha1_info_hash[i] != ((bmh_peer->sha1_info_hash)[i])) {
                        return 1;
                }
        }
        return 0;
}

struct metadata_info
{	
	int metadata_size; // the length in bytes of the metadata file
	int ut_metadata;   // integer identifier that specifies the extended message id (see bep 10 and bep 9)
};

// buff gives the starting address of a sequence of digits in ascii.
// This function returns the zero starting index of the first non-decimal
// character in buff. If *buff is not a decimal digit character this function
// returns 0
int skip_decimal_digits(char *buff)
{
	int index = 0;
	while ((buff[index] == '0') ||
	       (buff[index] == '1') ||
	       (buff[index] == '2') ||
	       (buff[index] == '3') ||
	       (buff[index] == '4') ||
               (buff[index] == '5') ||
               (buff[index] == '6') ||
               (buff[index] == '7') ||
	       (buff[index] == '8') ||
               (buff[index] == '9')) {
		++index;
	}
	return index;
}

//forward declaration
int skip_object(char *buff);

// buff points to the start of a bencoded integer. this function returns
// the zero starting index of the next byte in the buffer that comes after the
// integer
int skip_integer(char *buff)
{	
	int index = 0;
	++index; // skip 'i'
        while (buff[index] != 'e') {
        	 ++index;
	}
	++index;
	return index;
}

// Similar to skip_integer but skips a bencoded list
int skip_list(char *buff)
{
	int index = 0;
	++index; // skip 'l'
	while (buff[index] != 'e') {
		index += skip_object(&(buff[index]));
	}
	++index;
	return index;
}

// Similar to skip_list and skip_integer but skips a dictionary
int skip_dictionary(char *buff)
{
	int index = 0;
	++index; // skip 'd'
	while (buff[index]!= 'e') {
		index += skip_object(&(buff[index])); // skip name
		index += skip_object(&(buff[index])); // skip value	
	}
	++index;
	return index;
}

// buff is the address where a bencoded object (string, integer, list, or
// dictionary) starts and this function returns a zero starting index 
// such that buff[index] is the first byte after the object buff is pointing to
int skip_object(char *buff)
{
	int index = 0;
	char *invalid_char_addr = 0;
	int str_len = strtol(buff, &invalid_char_addr, 10);
	if ((str_len == 0) && (invalid_char_addr == buff)) {
		// object is not a string
		if (buff[0] == 'i') {
			// object is an integer
			return skip_integer(buff);
		}
		else if (buff[0] == 'l') {
			// object is a list
			return skip_list(buff);
		}
		else if (buff[0] == 'd') {
			return skip_dictionary(buff);
		}
	}
	else {
		// object is a string
		index = skip_decimal_digits(buff);
		++index; // skip ':'
		index += str_len;
		return index;
	}
}

// buff is the address of a bencoded dictionary.
// this function returns the index where the dictionary
// names 'm' starts. (This is used in the extension protocol see bep 10).
// This function returns -1 on error.
int get_m_dict(unsigned char *buff)
{
	int pos = 6;
	if (buff[pos++] != 'd') {
		return -1;
	}
	while (1) {
		char *invalid_char_addr = 0;
		int name_len = strtol(&(buff[pos]), &invalid_char_addr, 10);
		if ((name_len == 0) && (invalid_char_addr == ((char *)&(buff[pos])))) {
			// no number encountered. no string present
			return -1;
		}
		pos += skip_decimal_digits(&(buff[pos]));
		if (buff[pos++]!=':') {
			return -1;
		}
		char *name = (char *)malloc(name_len+1);
		memcpy(name, &(buff[pos]), name_len);
		name[name_len] = 0;
		if ((name_len == 1) && (name[0] == 'm')) {
			++pos;
			free(name);
			return pos;
		}
		free(name);
		pos += name_len;
		int index = skip_object(&(buff[pos]));
		pos += index;
	}
}

// buff points to the start of the bencoded m dictionary in the extension
// protocol handshake. This function returns the ut_metadata integer value
// within the m dictionary or returns 0 on error
int extract_ut_metadata(char *buff)
{
	char *key = "ut_metadata";
	int key_len = strlen(key);
	int pos = 0;
	if (buff[pos++] != 'd') {
		return 0;
	}
	while ( buff[pos] != 'e') {
		char *invalid_char_addr = 0;
                int name_len = strtol(&(buff[pos]), &invalid_char_addr, 10);
                if ((name_len == 0) && (invalid_char_addr == &(buff[pos]))) {
                        // no number encountered. no string present
                        return 0;
                }
                pos += skip_decimal_digits(&(buff[pos]));
                if (buff[pos++]!=':') {
                        return 0;
                }
                char *name = (char *)malloc(name_len+1);
                memcpy(name, &(buff[pos]), name_len);
                name[name_len] = 0;
                if ( (strncmp(name, key, key_len) == 0) && 
		     (name_len==key_len) ) {
			// ut_metadata name hit
			free(name);
                        pos += name_len;
                        if (buff[pos++] != 'i') {
				return 0; // expected bencoded integer
			}
			invalid_char_addr = 0;
			int ut_metadata = strtol(&(buff[pos]), 
					         &invalid_char_addr,
						 10);
			if ( (ut_metadata == 0) && 
			     (invalid_char_addr == &(buff[pos])) ) {
				return 0; // no integer value found
			}
			else {
				return ut_metadata;
			}
                }
                free(name);
                pos += name_len;
                int index = skip_object(&(buff[pos]));
                pos += index;
	}
	return 0; // end of dictionary reached
}

// buff points the the bencoded dictionary payload of the extension protocol
// handshake. This function returns the integer value of the "metadata_size" name,
// or -1 on error.
int extract_metadata_size(char *buff)
{
	char *key = "metadata_size";
        int key_len = strlen(key);
        int pos = 0;
	if (buff[pos++] != 'd') {
		return -1;
	}
	while (buff[pos] != 'e') {
		char *invalid_char_addr = 0;
                int name_len = strtol(&(buff[pos]), &invalid_char_addr, 10);
                if ((name_len == 0) && (invalid_char_addr == &(buff[pos]))) {
                        // no number encountered. no string present
                        return -1;
                }
                pos += skip_decimal_digits(&(buff[pos]));
                if (buff[pos++]!=':') {
                        return -1;
                }
                char *name = (char *)malloc(name_len+1);
                memcpy(name, &(buff[pos]), name_len);
                name[name_len] = 0;
                if ( (strncmp(name, key, key_len) == 0) &&
                     (name_len==key_len) ) {
                        // metadata_size name hit
                        free(name);
                        pos += name_len;
                        if (buff[pos++] != 'i') {
                                return -1; // expected bencoded integer
                        }
                        invalid_char_addr = 0;
                        int metadata_size = strtol(&(buff[pos]),
                                                 &invalid_char_addr,
                                                 10);
                        if ( (metadata_size == 0) &&
                             (invalid_char_addr == &(buff[pos])) ) {
                                return -1; // no integer value found
                        }
                        else {
                                return metadata_size;
                        }
                }
                free(name);
                pos += name_len;
                int index = skip_object(&(buff[pos]));
                pos += index;
	}
	return -1; // end of dictionary
}


// This function reads the extension protocol handshake message supplied in buff and
// fills the metadata_info structure at address mdi. If buff does not contain
// both a ut_metadata integer and a metadata_size then metadata_size is set to -1 (and ut_metadata set to 0) to
// indicate that the required info wasn't contained within buff.
void retrieve_metadata_info(unsigned char *buff, struct metadata_info *mdi)
{
	unsigned int *payload_len_ptr = (unsigned int *)buff;
	unsigned int payload_len = ntohl(*payload_len_ptr);
	if (buff[5]!=0) {
		printf("Extension protocol message is not a handshake message.\n");
		mdi->metadata_size = -1;
		mdi->ut_metadata = 0;
		return;
	}
	int m_dictionary_index = get_m_dict(buff);
	mdi->ut_metadata = extract_ut_metadata(&(buff[m_dictionary_index])); // correct up to here
	mdi->metadata_size = extract_metadata_size(&(buff[6]));
}

// metadata_info_dictionary is the metadata_info bencoded dictionary as an array.
// We parse through it and populate the structure pointed to by mi_data_ptr.
// All client-peer connections will share mi_data_ptr through their shared state.
// This function returns 0 on success. 1 on failure
unsigned char fill_metadata_info_struct(unsigned char *metadata_info_dictionary,
                               struct metadata_file_info_dict *mi_data_ptr)
{
	// default initialize mi_data_ptr
	mi_data_ptr->name = 0; // the suggested name of the downloaded file
        mi_data_ptr->piece_length = 0; // The length in bytes of each piece of the file
        mi_data_ptr->pieces = 0; // an array of pieces_length bytes (which is a multiple of 20)
        mi_data_ptr->pieces_length = 0; // length of pieces array in bytes. Must be a multiple of 20
        mi_data_ptr->length = 0; // Only non zero if we are downloading a single
        mi_data_ptr->files = 0;
        
	char *name_key = "name";
	char *piece_length_key = "piece length";
	char *pieces_key = "pieces";
	char *length_key = "length";
	char *files_key = "files";
	
	int pos = 0;
	if (metadata_info_dictionary[pos++] != 'd') {
		return 1;	
	}
	while (metadata_info_dictionary[pos] != 'e') {
		char *invalid_char_addr = 0;
		int key_name_len = strtol(&(metadata_info_dictionary[pos]), &invalid_char_addr, 10);
		if ( ((key_name_len == 0) && (invalid_char_addr == &(metadata_info_dictionary[pos]))) ||
	             (key_name_len == 0))	{
			// error, expected key name in dictionary (a string of positive length);
			printf("Error extracting data from metadata_info_dictionary into struct. Expected key name (string) in dictionary.\n");
			return 1;
		}	
		pos += skip_decimal_digits(&(metadata_info_dictionary[pos]));
		if (metadata_info_dictionary[pos++] != ':') {
			printf("Error extracting data from metadata_info_dictionary into struct. Expected colon for string.\n");
			return 1; // dictionary ill formed, expected colon for string
		}
		if ( (key_name_len == strlen(name_key)) &&
		     (strncmp(&(metadata_info_dictionary[pos]), name_key, key_name_len) == 0)) {
			// key is "name"
			pos += key_name_len;
			invalid_char_addr = 0;
			int name_len = strtol(&(metadata_info_dictionary[pos]), &invalid_char_addr, 10);
			if ( ((name_len == 0) && (&(metadata_info_dictionary[pos]) == invalid_char_addr))  ||
			     (name_len == 0)) {
				// expected integer defining the length of the name value
				printf("Error extracting data from metadata_info_dictionary into struct. Expected integer defining the length of the name string value.\n");
				return 1;
			}
			pos += skip_decimal_digits(&(metadata_info_dictionary[pos]));
			if (metadata_info_dictionary[pos++] != ':') {
				printf("Error extracting data from metadata_info_dictionary into struct. Expected colon for string.\n");
                        	return 1; // dictionary ill formed, expected colon for string
                	}
			mi_data_ptr->name = (char *)malloc(name_len + 1);
			memcpy(mi_data_ptr->name, &(metadata_info_dictionary[pos]), name_len);
			(mi_data_ptr->name)[name_len] = 0;
			pos += name_len;
		}
		else if ( (key_name_len == strlen(piece_length_key)) &&
			  (strncmp(&(metadata_info_dictionary[pos]), piece_length_key, key_name_len)==0) ) {
			// key is "piece length"
			pos += key_name_len;
			if (metadata_info_dictionary[pos++] != 'i') {
				printf("Error exracting data from metadata_info_dictionary into struct. Eexpected leading 'i' for an integer"
					"defining the \"piece length\"\n");
				return 1;
			}
			invalid_char_addr = 0;
			unsigned int piece_length = strtol(&(metadata_info_dictionary[pos]), &invalid_char_addr, 10);
			if ( ((piece_length == 0) && (&(metadata_info_dictionary[pos]) == invalid_char_addr)) ||
   				(piece_length == 0)) {
				printf("Error extracting data from metadata_info_dictionary into struct. Expected positive \"piece length\"\n");
				return 1; // nonpositive piece_length is an error
			}
			mi_data_ptr->piece_length = piece_length;
			pos += skip_decimal_digits(&(metadata_info_dictionary[pos]));
			if (metadata_info_dictionary[pos++] != 'e') {
				printf("Error extracting data from metadata_info_dictionary into struct. Expected an integer terminating 'e' for the \"piece length\" integer.\n");
				return 1;
			}		
		}
		else if ( (key_name_len == strlen(pieces_key)) &&
			  (strncmp(&(metadata_info_dictionary[pos]), pieces_key, key_name_len)==0) ) {
			// key is "pieces"
			pos += key_name_len;
			invalid_char_addr = 0;
			unsigned int pieces_len = strtol(&(metadata_info_dictionary[pos]), &invalid_char_addr, 10);
			if ( ((pieces_len == 0) && (&(metadata_info_dictionary[pos]) == invalid_char_addr)) ||
		             (pieces_len == 0) || ((pieces_len % 20)!= 0) )	{
		   		printf("\"pieces\" array in metadata_info_dictionary is not a multiple of 20 bytes long. \n");
				return 1;	
			}
			pos += skip_decimal_digits(&(metadata_info_dictionary[pos]));
			if (metadata_info_dictionary[pos++]!=':') {
				printf("Expected \"peices\" array in metadata_info_dictionary but no colon.\n");
				return 1;
			}
			mi_data_ptr->pieces = (unsigned char *)malloc(pieces_len);
			memcpy(mi_data_ptr->pieces, &(metadata_info_dictionary[pos]), pieces_len);
			mi_data_ptr->pieces_length = pieces_len;
			pos += pieces_len;
		}	
		else if ( (key_name_len == strlen(length_key)) &&
			  (strncmp(&(metadata_info_dictionary[pos]), length_key, key_name_len)==0) ) {
			// key is "length"
			pos += key_name_len;
			if (metadata_info_dictionary[pos++]!='i') {
				printf("Expected 'i' preceeding base 10 integer specifying the length of the individual file.\n");
				return 1;
			}
			invalid_char_addr = 0;
			unsigned long int length = strtol(&(metadata_info_dictionary[pos]), &invalid_char_addr, 10);
			if (((length ==0) && (&(metadata_info_dictionary[pos]) == invalid_char_addr)) ||
			    (length == 0)) {
				printf("Expected positive file length.\n");
				return 1;
			}
			mi_data_ptr->length = length;
			pos += skip_decimal_digits(&(metadata_info_dictionary[pos]));
			if (metadata_info_dictionary[pos++] != 'e') {
				printf("Expected 'e' terminating integer for the \"length\" dictionary name but none found.\n");
				return 1;
			}
		}
		else if ( (key_name_len == strlen(files_key)) &&
			  (strncmp(&(metadata_info_dictionary[pos]), files_key, key_name_len)==0) ) {
			// key is "files"
			char *path_key = "path";
			pos += key_name_len;
			if (metadata_info_dictionary[pos++] != 'l') {
				printf("Key files does not map to a list (of file length and paths) in the metadata_info_dictionary array.\n");
				return 1;
			}
			while (metadata_info_dictionary[pos]!='e') {
				struct file curr_file;
				if (metadata_info_dictionary[pos++] != 'd') {
					printf("Error expected dictionary in list of files.\n");
					return 1;
				}	
				while (metadata_info_dictionary[pos] != 'e') {
					invalid_char_addr = 0;
					int sub_dict_key_name_len = strtol(&(metadata_info_dictionary[pos]),
								           &invalid_char_addr,
									   10);
					if ( ((sub_dict_key_name_len == 0) &&
					      (&(metadata_info_dictionary[pos]) == invalid_char_addr)) ||
				             (sub_dict_key_name_len == 0) )	{
						printf("Expected positive integer specifying sub dictionary string key length.\n");
						return 1;
					}
					pos += skip_decimal_digits(&(metadata_info_dictionary[pos]));
					if (metadata_info_dictionary[pos++] != ':') {
						printf("Expected colon defining sub dictionary key name string.\n");
						return 1;
					}
					if ( (sub_dict_key_name_len == strlen(length_key)) && 
					     (strncmp(&(metadata_info_dictionary[pos]), length_key, sub_dict_key_name_len)==0)) {
						// key is "length"
						pos += sub_dict_key_name_len;
						if (metadata_info_dictionary[pos++] != 'i') {
							printf("Expected 'i' preceeding integer defining file length.\n");
							return 1;
						}	
						invalid_char_addr = 0;
						unsigned long int file_len = strtol(&(metadata_info_dictionary[pos]),
									   		&invalid_char_addr,
								           		10);
						if ( ((file_len == 0) && (invalid_char_addr == &(metadata_info_dictionary[pos]))) ||
						     (file_len == 0) ) {
							printf("Expected positive file length.\n");
							return 1;
						}
						pos += skip_decimal_digits(&(metadata_info_dictionary[pos]));
						if (metadata_info_dictionary[pos++] != 'e') {
							printf("Expected 'e' to terminate file length integer.\n");
							return 1;
						}
				     		curr_file.length = file_len;		
					}
					else if ( (sub_dict_key_name_len == strlen(path_key)) &&
						  (strncmp(&(metadata_info_dictionary[pos]), path_key, sub_dict_key_name_len)==0) ) {
						// key is "path"
						pos += 	sub_dict_key_name_len;
						if (metadata_info_dictionary[pos++] != 'l') {
							printf("Expected list of strings to define a file path.\n");
							return 1;
						}
						int path_component_index = 0;
						while (metadata_info_dictionary[pos] != 'e') {
							invalid_char_addr = 0;
							unsigned int path_component_len = strtol(&(metadata_info_dictionary[pos]), 
									                         &invalid_char_addr,
												 10);
							if ( ((path_component_len == 0) &&
							      (&(metadata_info_dictionary[pos]) == invalid_char_addr)) ||
							     (path_component_len == 0) ) {
								printf("Expected file path component of positive length.\n");
								return 1;
							}
							pos += skip_decimal_digits(&(metadata_info_dictionary[pos]));
							if (metadata_info_dictionary[pos++] != ':') {
								printf("Expected colon in string bencoded formar.\n");
								return 1;
							}
							if (path_component_index == 0) {
								curr_file.path = (char *)malloc(path_component_len + 1);
								memcpy(curr_file.path, &(metadata_info_dictionary[pos]), path_component_len);
								(curr_file.path)[path_component_len] = 0;
							}				
							else {
								int curr_file_path_len = strlen(curr_file.path);
								char *temp_complete_path = (char *)malloc(curr_file_path_len + 1 + path_component_len + 1);
								memcpy(temp_complete_path, curr_file.path, curr_file_path_len);
								temp_complete_path[curr_file_path_len] = '/';
								memcpy(&(temp_complete_path[curr_file_path_len+1]), &(metadata_info_dictionary[pos]), path_component_len);
								temp_complete_path[curr_file_path_len + 1 + path_component_len] = 0;
								free(curr_file.path);
								curr_file.path = temp_complete_path;
							}
							pos += path_component_len;
							++path_component_index;
						}
						++pos;

					}
					else {
						// unrecognised dictionary key name. skip the name and associated value.
						pos += sub_dict_key_name_len; // skip unrecognised name
						pos += skip_object(&(metadata_info_dictionary[pos])); // skip value    
					}
				}
				// insert curr_file into mi_data_ptr->files
				if ((mi_data_ptr->files)==0) {
					mi_data_ptr->files = init_dlist(sizeof(struct file), 0); // provided no compare function so far
					dlist_push_back(mi_data_ptr->files, (void *)&curr_file);
				}
				else {
					dlist_push_back(mi_data_ptr->files, (void *)&curr_file);
				}
				++pos;
			}
			++pos;
		}
		else {
			// handle all other dictionary name keys and associated values
			pos += key_name_len;
			pos += skip_object(&(metadata_info_dictionary[pos]));
		}
	}
	return 0;
}

struct metadata_block_request
{
	unsigned int payload_len;
	unsigned char message_type; // 20 for extension protocol
	unsigned char message_id; // peer dependent message id that specifies peers sending metadata info dictionary bep 9
	unsigned char request[42];
};


// x and y both point to words (byte arrays of length 4) that are
// considered as 4 byte integers big endian and their addition
// (mod 2^32) is returned as a 4 byte big endian array dynamically 
// allocated on the heap which must be freed
unsigned char *addition(unsigned char *x, unsigned char *y)
{
	unsigned int *x_int = (unsigned int *)x;
	unsigned int *y_int = (unsigned int *)y;
	unsigned long int sum = (unsigned long int)(ntohl(*x_int)) + (unsigned long int)(ntohl(*y_int));
	unsigned char *result = (unsigned char *)malloc(4);
	sum = htobe64(sum);
	unsigned char *sum_addr = (unsigned char *)&sum;
	sum_addr += 4;
	memcpy(result, sum_addr, 4);
	return result;
}

// circular left shift x by n bits. x is unchanged and
// the result is dynamically allocated on the heap and returned.
// x and the returned integer are 4 bytes big endian.
unsigned char *circular_left_shift(unsigned char *x, int n)
{
	unsigned int *x_addr = (unsigned int *)x;
	unsigned int x_val = ntohl(*x_addr);
	unsigned int x_val_left = x_val << n;
	unsigned int x_val_right = x_val >> (32-n);
	x_val = x_val_left + x_val_right;
	unsigned char *x_shifted = (unsigned char *)malloc(4);
	x_addr = (unsigned int *)x_shifted;
	*x_addr = htonl(x_val);
	return x_shifted;
}

// rfc 3174 functions and constants used implementation of f
unsigned char *f(int t, unsigned char *B, unsigned char *C, unsigned char *D)
{
	unsigned char *result = (unsigned char *)malloc(4);
	if ((0<=t) && (t<=19)) {
		for (int i=0; i<4; ++i) {
			result[i] = (B[i] & C[i]) | ((~(B[i])) & D[i]);
		}
	}
	else if ((20<=t) && (t<=39)) {
		for (int i =0; i<4; ++i) {
			result[i] = B[i] ^ C[i] ^ D[i];
		}
	}
	else if ((40<=t) && (t<=59)) {
		for (int i=0; i<4; ++i) {
			result[i] = (B[i] & C[i]) | (B[i] & D[i]) | (C[i] & D[i]);
		}
	}
	else if ((60<=t) && (t<=79)) {
                for (int i =0; i<4; ++i) {
                        result[i] = B[i] ^ C[i] ^ D[i];
                }
        }
	return result;
}

// rfc 3174 functions and constants implementation of K
unsigned char *K(int t)
{
	unsigned char *res = (unsigned char *)malloc(4);
	if ((0<=t) && (t<=19)) {
		res[0] = 0x5a;
		res[1] = 0x82;
		res[2] = 0x79;
		res[3] = 0x99;
	}
	else if ((20<=t) && (t<=39)) {
		res[0] = 0x6e;
		res[1] = 0xd9;
		res[2] = 0xeb;
		res[3] = 0xa1;
	}
	else if ((40<=t) && (t<=59)) {
		res[0] = 0x8f;
		res[1] = 0x1b;
		res[2] = 0xbc;
		res[3] = 0xdc;
	}
	else if ((60<=t) && (t<=79)) {
		res[0] = 0xca;
		res[1] = 0x62;
		res[2] = 0xc1;
		res[3] = 0xd6;
	}
	return res;
}

// buff is a buffer of len bytes. This function padds buff so it
// is a 512*n bits long fror some n>0. (see rfc7174).
// The returned padded buffer is dynamically allocated and must be
// eventually freed
unsigned char *padd_message(unsigned char *buff, unsigned long int len)
{
	unsigned long int new_len = 0;
	unsigned char *padded_message;
	if ((len % 64) == 0) {
		new_len = len + 64;
		padded_message = (unsigned char *)malloc(new_len);
        	memcpy(padded_message, buff, len);
        	padded_message[len] = 0x80;
        	memset(&(padded_message[len+1]), 0, 55);
		unsigned long int *append_len_address = (unsigned long int *)&(padded_message[new_len-8]);
	        *append_len_address = htobe64(len*8);	
	}
	else if ((len % 64) <= 55) {
		new_len = len + (64 - (len % 64));
                padded_message = (unsigned char *)malloc(new_len);
                memcpy(padded_message, buff, len);
                padded_message[len] = 0x80;
		int zeros_len = 55 - (len % 64);
		if (zeros_len > 0) {
                	memset(&(padded_message[len+1]), 0, zeros_len);
		}
                unsigned long int *append_len_address = (unsigned long int *)&(padded_message[new_len-8]);
                *append_len_address = htobe64(len*8);
	}
	else {
		new_len = len + (64 - (len % 64)) + 64;
		padded_message = (unsigned char *)malloc(new_len);
                memcpy(padded_message, buff, len);
                padded_message[len] = 0x80;
                int zeros_len = (64 - (len % 64)) + 64 - 9;
                if (zeros_len > 0) {
                        memset(&(padded_message[len+1]), 0, zeros_len);
                }
                unsigned long int *append_len_address = (unsigned long int *)&(padded_message[new_len-8]);
                *append_len_address = htobe64(len*8);
	}
	return padded_message;
}

// This function returns a dynamically allocated array of 20 bytes which is the sha1 hash of
// buff where buff is of length bytes.
unsigned char *compute_sha1_hash(unsigned char *buff, int length)
{
	unsigned char *padded_message = padd_message(buff, length);
	
	int padded_message_len = 0;
	if ((length % 64)==0) {
		padded_message_len = length + 64;
	}
	else if ( (length % 64) <= 55 ) {
		padded_message_len = length + (64 - (length % 64));
	}
	else {
		padded_message_len = length + (64 - (length % 64)) + 64;
	}

	/*printf("padded_message: ");
	for (int i=0; i<padded_message_len; ++i) {
		printf("%x",padded_message[i]);
	}
        printf("\n");	*/
	unsigned char H0[4] = {0x67,0x45,0x23,0x01};
	unsigned char H1[4] = {0xef,0xcd,0xab,0x89};
	unsigned char H2[4] = {0x98,0xba,0xdc,0xfe};
	unsigned char H3[4] = {0x10,0x32,0x54,0x76};
	unsigned char H4[4] = {0xc3,0xd2,0xe1,0xf0};	
	unsigned char A[4] = {0};
	unsigned char B[4] = {0};
	unsigned char C[4] = {0};
	unsigned char D[4] = {0};
	unsigned char E[4] = {0};
	unsigned char TEMP[4] = {0};

	unsigned char *W = (unsigned char *)malloc(80*4);

	for (int i=0; i<(padded_message_len/64); ++i) {
		for (int j=0; j<16; ++j) {
			memcpy(&(W[j*4]), &(padded_message[(i*64)+(j*4)]), 4);
		}	
		for (int j=16; j<=79; ++j) {
			unsigned char wj_temp[4];
			for (int k=0; k<4; ++k) {
				wj_temp[k] = W[(j-3)*4 + k] ^
					     W[(j-8)*4 + k] ^
					     W[(j-14)*4 + k] ^
					     W[(j-16)*4 + k];
			}
			unsigned char *wj = circular_left_shift(wj_temp, 1);
			memcpy(&(W[j*4]), wj, 4);
			free(wj);
		}
		memcpy(A,H0,4);
		memcpy(B,H1,4);
		memcpy(C,H2,4);
		memcpy(D,H3,4);
		memcpy(E,H4,4);
		for (int j=0; j<=79; ++j) {
			unsigned char *A_shifted = circular_left_shift(A, 5);
			unsigned char *f_val = f(j,B,C,D);
			unsigned char *sum0 = addition(A_shifted, f_val);
			free(f_val);
			free(A_shifted);
			unsigned char *sum1 = addition(sum0, E);
			free(sum0);
			unsigned char *sum2 = addition(sum1, &(W[j*4]));
			free(sum1);
			unsigned char *K_val = K(j);
			unsigned char *temp = addition(sum2, K_val);
		       	free(K_val);
			free(sum2);	
			memcpy(E,D,4);
			memcpy(D,C,4);
			unsigned char *B_shifted = circular_left_shift(B,30);
			memcpy(C,B_shifted,4);
			free(B_shifted);
			memcpy(B,A,4);
			memcpy(A,temp,4);
			free(temp);
		}
		unsigned char *sum0 = addition(H0,A);
		memcpy(H0,sum0,4);
		free(sum0);
		unsigned char *sum1 = addition(H1,B);
                memcpy(H1,sum1,4);
                free(sum1);
		unsigned char *sum2 = addition(H2,C);
                memcpy(H2,sum2,4);
                free(sum2);
		unsigned char *sum3 = addition(H3,D);
                memcpy(H3,sum3,4);
                free(sum3);
		unsigned char *sum4 = addition(H4,E);
                memcpy(H4,sum4,4);
                free(sum4);
	}
	unsigned char *msg_digest = (unsigned char *)malloc(20);
	memcpy(msg_digest,H0,4);
	memcpy(&(msg_digest[4]), H1, 4);
	memcpy(&(msg_digest[8]), H2, 4);
	memcpy(&(msg_digest[12]), H3, 4);
	memcpy(&(msg_digest[16]), H4, 4);
	free(padded_message);
	return msg_digest;
}

// function returns 1 if obtained_hash matched sha1_info_hash.
// Otherwise 0 is returned. Both arrays are of length 20 bytes
unsigned char valid_metadata_hash(unsigned char *obtained_hash, 
				  unsigned char *sha1_info_hash)
{
	for (int i=0; i<20; ++i) {
		if (obtained_hash[i]!=sha1_info_hash[i]) {
			return 0;
		}
	}
	return 1;
}


// struct for holding the number of peers that have a specific piece (index) of the download
struct peers_piece
{
	unsigned int piece_index;
	unsigned int count;
};

// p1 and p2 refer to the addresses of two different peers_piece structs
// this function returns the address of the greater of the two unless both
// are equal in which case the function returns NULL
void *compare_peers_piece(void *p1, void *p2)
{
	struct peers_piece *pp1 = (struct peers_piece *)p1;
	struct peers_piece *pp2 = (struct peers_piece *)p2;
	if ((pp1->piece_index) < (pp2->piece_index)) {
		return p2;
	}
	else if ( (pp1->piece_index) > (pp2->piece_index) ) {
		return p1;
	}
	else {
		return 0;
	}
}

// prints the peers_piece at address p
void print_peers_piece(void *p)
{
	struct peers_piece *p1 = (struct peers_piece *)p;
	printf("piece_index:%u count:%u", p1->piece_index, p1->count);
}

// piece_msg is a buffer that we fill with data from the request p
// and our download metatada info mi. This function returns 0 on success
// and 1 on failure.
int fill_piece_msg(unsigned char *piece_msg, 
		   struct metadata_file_info_dict *mi, 
		   struct request *p)
{
	unsigned int piece_index = p->piece_index;
	unsigned int begin = p->begin;
	unsigned int length = p->length;

}

// creates/initializes the downloaded files in ~/Downloads. This function
// returns 0 in success, 1 on failure. 
int create_files(struct metadata_file_info_dict *mi_data_ptr)
{
	if ((mi_data_ptr->length) > 0) {
		// we are downloading only a single file
		char path[1000] = {0};
        	sprintf(path, "%s/Downloads/%s", getenv("HOME"), mi_data_ptr->name);
        	FILE *fp = fopen(path, "w+");
        	if (!fp) {
                	printf("Error initializing file %s. %s.",path, strerror(errno));
                	return 1;
        	}	
        	int res = ftruncate(fileno(fp), 10000);
        	if (res==-1) {
        	        printf("Error truncating file %s to %lu bytes.\n", path, mi_data_ptr->length);
        	        return 1;
        	}
	 	fclose(fp);
		return 0;	
	}
	else {
		// we are downloading multiple files
		struct stat st = {0};
		char dir_path[2000] = {0};
                sprintf(dir_path, "%s/Downloads/%s", getenv("HOME"), mi_data_ptr->name);
		int stat_res = stat(dir_path, &st);
		if ((stat_res==-1) && (errno == ENOENT)) {
			int res = mkdir(dir_path, 0777);
			if (res==-1) {
				printf("Error occurred when creating directory %s. %s\n", dir_path, strerror(errno));
				return 1;
			}
			dir_path[strlen(dir_path)]='/';	
			int base_pos = strlen(dir_path);
			int pos = 0;
			struct doubly_linked_list *files = mi_data_ptr->files;
			// path length
			struct  link *curr_link = dlist_beg(files);
			while (curr_link != dlist_end(files)) {
				char file_path[2000] = {0};
				memcpy(file_path, dir_path, strlen(dir_path));
				struct file *f = (struct file *)dlist_get_val(curr_link);
				while (1) {
					unsigned char directory_required = 0;
					int temp_pos = pos;
					while ((((f->path)[temp_pos]) != '/') && (temp_pos < strlen(f->path))) {
						++temp_pos;
					}	
					if (((f->path)[temp_pos]) == '/') {
						directory_required = 1;
					}
					if (directory_required) {
						memcpy(&(file_path[base_pos]), &((f->path)[pos]), temp_pos - pos);
						struct stat s = {0};
						stat_res = stat(file_path, &s);
						if ((stat_res == -1) && (errno == ENOENT)) {
							res = mkdir(file_path, 0777);
								if (res == -1) {
									printf("Error creating intermediate directory %s. %s\n", file_path,strerror(errno));
								return 1;
							}
						}
					}	
					else {
						break;
					} 
					base_pos += (temp_pos - pos);
					file_path[base_pos++] = '/';
					pos = temp_pos + 1;
				}
				memcpy(&(file_path[base_pos]), &((f->path)[pos]), strlen(f->path) - pos);
				// now possible to create file
				FILE *fp = fopen(file_path, "w+");
               			if (!fp) {
                        		printf("Error initializing file %s. %s.",file_path, strerror(errno));
                        		return 1;
               			}
                		int res = ftruncate(fileno(fp), f->length);
                		if (res==-1) {
                		        printf("Error truncating file %s to %lu bytes.\n", file_path, f->length);
                        		return 1;
                		}
                		fclose(fp);
				pos = 0;
				base_pos = strlen(dir_path);
				curr_link = dlist_succ(curr_link);
			}
			return 0;			
		}	
		else if (stat_res == -1) {
			printf("Error occurred checking status of directory %s.\n", dir_path);
			return 1;
		}
		else {
			// Base directory already present
			dir_path[strlen(dir_path)]='/';
                        int base_pos = strlen(dir_path);
                        int pos = 0;
                        struct doubly_linked_list *files = mi_data_ptr->files;
                        // path length
                        struct  link *curr_link = dlist_beg(files);
                        while (curr_link != dlist_end(files)) {
                                char file_path[2000] = {0};
                                memcpy(file_path, dir_path, strlen(dir_path));
                                struct file *f = (struct file *)dlist_get_val(curr_link);
                                while (1) {
                                        unsigned char directory_required = 0;
                                        int temp_pos = pos;
                                        while ((((f->path)[temp_pos]) != '/') && (temp_pos < strlen(f->path))) {
                                                ++temp_pos;
                                        }
                                        if (((f->path)[temp_pos]) == '/') {
                                                directory_required = 1;
                                        }
                                        if (directory_required) {
                                                memcpy(&(file_path[base_pos]), &((f->path)[pos]), temp_pos - pos);
                                                struct stat s = {0};
                                                stat_res = stat(file_path, &s);
						if ((stat_res == -1) && (errno == ENOENT)) {
						int res = mkdir(file_path, 0777);
                                                	if (res == -1) {
                                                        	printf("Error creating intermediate directory %s. %s\n", file_path, strerror(errno));
                                                        	return 1;
                                                	}
						}
                                        }
                                        else {
                                                break;
                                        }
                                        base_pos += (temp_pos - pos);
                                        file_path[base_pos++] = '/';
                                        pos = temp_pos + 1;
                                }
                                memcpy(&(file_path[base_pos]), &((f->path)[pos]), strlen(f->path) - pos);
				// now possible to create file
                                FILE *fp = fopen(file_path, "w+");
                                if (!fp) {
                                        printf("Error initializing file %s. %s.",file_path, strerror(errno));
                                        return 1;
                                }
                                int res = ftruncate(fileno(fp), f->length);
                                if (res==-1) {
                                        printf("Error truncating file %s to %lu bytes.\n", file_path, f->length);
                                        return 1;
                                }
                                fclose(fp);
                                pos = 0;
                                base_pos = strlen(dir_path);
                                curr_link = dlist_succ(curr_link);
                        }
                        return 0;		
		}
	}
}

void *obtain_metadata_info(void *per_thread_data) 
{ 
        // per thread data
	struct obtain_metadata_info_per_thread_data *ptd = (struct obtain_metadata_info_per_thread_data *)per_thread_data;

	unsigned char recv_buff[20000];

	char *bittorrent_header_text = "BitTorrent protocol";
        struct bittorrent_main_handshake bmh;
        bmh.len_19_prefix = 19;
        memcpy(bmh.bittorrent_protocol, bittorrent_header_text, 19);
        memset(bmh.reserved_bytes, 0, 8);
        bmh.reserved_bytes[5] = 0x10;
        extract_info_hash(ptd->magnet_link, bmh.sha1_info_hash);
        memcpy(bmh.peer_id, ptd->peer_id, 20);

	ptd->client_socket_fd = socket(AF_INET, SOCK_STREAM, 6); // TCP socket
	int client_socket_fd = ptd->client_socket_fd;
        if (client_socket_fd == -1) {
        	printf("Error obtaining tcp/ip socket client endpoint.\n");
	}

	socklen_t sock_len = sizeof(struct sockaddr);
	if (connect(client_socket_fd, (struct sockaddr *)&(ptd->peer), sock_len)!= 0) {
		printf("Error connecting to peer through tcp/ip. %s\n", strerror(errno));
		close(client_socket_fd);
		return 0;
	}
	ssize_t sent_bytes = send(client_socket_fd, &bmh, sizeof(struct bittorrent_main_handshake), 0);
	if (sent_bytes != sizeof(struct bittorrent_main_handshake)) {
		printf("Error sending bittorrent main handshake, only sent %d bytes.\n", sent_bytes);
		close(client_socket_fd);
		return 0;
	}
	
	struct bittorrent_main_handshake *bmh_peer = (struct bittorrent_main_handshake *)recv_buff;
	ssize_t recv_bytes = 0;
	while (recv_bytes < sizeof(struct bittorrent_main_handshake)) {
		ssize_t new_bytes = recv(client_socket_fd, &(recv_buff[recv_bytes]), 20000 - recv_bytes, 0);
		if (new_bytes == -1) {
			printf("Error receiving bittorrent main handshake from peer. Thread terminating.\n");
			close(client_socket_fd);
			return 0;
		}
		else if (new_bytes == 0) {
			close(client_socket_fd);
			return 0; // peer closed connection
		}
		else {
			recv_bytes += new_bytes;
		}
	}
	if (check_peer_handshake(bmh.sha1_info_hash, bmh_peer)!=0) {
		printf("Bittorrent main handshake sent from peer invalid.\n");
		close(client_socket_fd);
		return 0;
	}	
	printf("Successful handshake received from peer %s!\n", inet_ntoa((ptd->peer).sin_addr));
	int bmh_len = (int)sizeof(struct bittorrent_main_handshake);
	printf("sizeof struct bmh: %d  recv_bytes:%u\n", bmh_len, recv_bytes);
	for (int i = 0; i<(recv_bytes - bmh_len); ++i) {
		recv_buff[i] = recv_buff[bmh_len + i];
	}
	recv_bytes -= bmh_len;
	// obtain extended
	unsigned int payload_len = 0;
	while (1) {
		while (recv_bytes < 4) {
			int new_bytes = recv(client_socket_fd, &(recv_buff[recv_bytes]), 20000 - recv_bytes, 0);
			if (new_bytes == -1) {
				printf("Error whilst attempting to receive extension protocol handshake. Thread terminating.");
				close(client_socket_fd);
				return 0;
			}
			else if (new_bytes == 0) {
				close(client_socket_fd);
				return 0; // peer closed connection
			}
			else {
				recv_bytes += new_bytes;
			}
		}
		unsigned int *payload_len_ptr = (unsigned int *)recv_buff;
		payload_len = ntohl(*payload_len_ptr);
		printf("payload len: %u from peer %s\n", payload_len, inet_ntoa((ptd->peer).sin_addr));
		if (payload_len == 0) {
			// received keep alive message
			for (int i = 0; i<(recv_bytes -4); ++i) {
                        	recv_buff[i] = recv_buff[4 + i];
                	}
			recv_bytes -= 4;
			continue;
		}
		while (recv_bytes < (4 + payload_len)) {
			int new_bytes = recv(client_socket_fd, &(recv_buff[recv_bytes]), 20000-recv_bytes, 0);
                        if (new_bytes == -1) {
                                printf("Error whilst attempting to receive extension protocol handshake. Thread terminating.");
                                close(client_socket_fd);
                                return 0;
                        }
                        else if (new_bytes == 0) {
                                close(client_socket_fd);
                                return 0; // peer closed connection
                        }
                        else {
                                recv_bytes += new_bytes;
                        }
		}
		if (recv_buff[4]==20) {
			// client received extension protocol handshake
			break;
		}
		for (int i = 0; i<(recv_bytes - (4+payload_len)); ++i) {
                	recv_buff[i] = recv_buff[(4+payload_len) + i];
        	}
      	 	recv_bytes -= (4+payload_len);
	}
	printf("Extended message received.\n");
	struct metadata_info mdi;
	retrieve_metadata_info(recv_buff, &mdi);
	if (((mdi.ut_metadata) == 0) || ((mdi.metadata_size) == -1)) {
		close(client_socket_fd);
                return 0; // error retrieving ut_metadata or metadata_size
        }
	for (int i = 0; i<(recv_bytes - (4+payload_len)); ++i) {
		recv_buff[i] = recv_buff[(4+payload_len) + i];
	}
	recv_bytes -= (4+payload_len);
	
	unsigned char *metadata = (unsigned char *)malloc(mdi.metadata_size);

	int metadata_blocks = (mdi.metadata_size)/16384;
	if (((mdi.metadata_size) % 16384) != 0) {
		++metadata_blocks;
	}
	while (1) {
		memset(metadata, 0, mdi.metadata_size);
		pthread_mutex_lock(ptd->metadata_info_dict_mutex);
		if ((*(ptd->metadata_info_dictionary))!=0) {
			pthread_mutex_unlock(ptd->metadata_info_dict_mutex);
			break; // metadata_info_dictionary already obtained and checked against hash to match
		}
		pthread_mutex_unlock(ptd->metadata_info_dict_mutex);
		unsigned char request_rejected = 0;
		for (int i=0; i<metadata_blocks; ++i) {
			struct metadata_block_request mbr;
			memset(mbr.request, 0, 42);
			sprintf(mbr.request, "d8:msg_typei0e5:piecei%dee", i);
			mbr.payload_len = htonl(strlen(mbr.request) + 2);
			mbr.message_type = 20;
			mbr.message_id = mdi.ut_metadata;
			ssize_t sent_bytes = send(client_socket_fd, &mbr, ntohl(mbr.payload_len) + 4, 0);
			if (sent_bytes != (strlen(mbr.request)+6)) {
				printf("Error sending request to peer for piece %d of the metadata info dictionary. sent bytes: %d. payload_len: %u. Thread terminating.\n", i, sent_bytes, ntohl(mbr.payload_len));
				close(client_socket_fd);
				return 0;
			}
			request_rejected = 0;
			unsigned char resend_piece_request = 0;
			unsigned char data_received = 0;
			while (1) {
				while (recv_bytes < 4) {
					int new_bytes = recv(client_socket_fd, &(recv_buff[recv_bytes]), 20000-recv_bytes, 0);
					if (new_bytes == -1) {
						printf("Error whilst attempting to receive metadata info dict piece %d. Thread terminating.\n", i);
						close(client_socket_fd);
						return 0;
					}
					else if (new_bytes == 0) {
						close(client_socket_fd);
						return 0; // peer closed connection
					}
					else {
						recv_bytes += new_bytes;
					}       
				}
				unsigned int *payload_len_ptr = (unsigned int *)recv_buff;
				payload_len = ntohl(*payload_len_ptr);
				if (payload_len == 0) {
					// received keep alive message
					for (int i = 0; i<(recv_bytes-4); ++i) {
						recv_buff[i] = recv_buff[4 + i];
					}
					recv_bytes -= 4;
					continue;
				}
				while (recv_bytes < (4 + payload_len)) {
				       int new_bytes = recv(client_socket_fd, &(recv_buff[recv_bytes]), 20000-recv_bytes, 0);
				       if (new_bytes == -1) {
					       printf("Error whilst attempting to receive metadata info dict piece %d. Thread terminating.\n", i);
					       close(client_socket_fd);
						return 0;
					}
					else if (new_bytes == 0) {
						close(client_socket_fd);
						return 0; // peer closed connection
					}
					else {
						recv_bytes += new_bytes;
					}
				}
				if (recv_buff[4]==20) {
					// client received extension protocol message, which is what we are looking for
					/*if (recv_buff[5] != mdi.ut_metadata) {
						printf("Peer %s sent extension protocol message id inconsistent with it's ut_metadata value. Thread terminating.\n", inet_ntoa((ptd->peer).sin_addr));
						close(client_socket_fd);
						return 0;
					}*/
					if (recv_buff[6+12]=='0') {
						// received request for metadata info dictionary piece
						char *endpoint = 0;
						int requested_index = strtol(&(recv_buff[6+22]), &endpoint, 10);
						if ((requested_index == 0) && (((void *)endpoint) ==  (void *)(&(recv_buff[6+22])))) {
							printf("Received request message for metadata info piece of incorrect format from peer %s. Thread terminating.\n", inet_ntoa((ptd->peer).sin_addr));
							close(client_socket_fd);
							return 0;
						}
						// reject the request
						char reject_message[40] = {0};
						sprintf(reject_message, "d8:msg_typei2e5:piecei%dee", requested_index);
						unsigned char *extension_reject_message = (unsigned char *)malloc(6 + strlen(reject_message));
						unsigned int *extension_reject_msg_payload_len = (unsigned int *)extension_reject_message;
						*extension_reject_msg_payload_len = htonl(6 + strlen(reject_message));
						extension_reject_message[4] = 20;
						extension_reject_message[5] = mdi.ut_metadata;
						memcpy(&(extension_reject_message[6]), reject_message, strlen(reject_message));
						ssize_t bytes_sent = send(client_socket_fd, 
								          extension_reject_message, 
									  6 + strlen(reject_message),
									  0);
						if (bytes_sent != (6 + strlen(reject_message))) {
							printf("Error sending extension ut_metadata reject message. Thread terminating. \n");
							close(client_socket_fd);
							return 0;
						}

					}
					else if (recv_buff[6+12]=='2') {
						// received rejection from peer as a response for metadata info piece request
						char reject_message[30] = {0};
						sprintf(reject_message, "d8:msg_typei2e5:piecei%dee", i);
						if (strncmp(&(recv_buff[6]), reject_message, strlen(reject_message))==0) {
							printf("Peer %s rejected metadata info piece request.\n", 
								inet_ntoa((ptd->peer).sin_addr));
							request_rejected = 1;
						}
						else {
							char *endpoint = 0;
                                               	 	int requested_index = strtol(&(recv_buff[6+22]), &endpoint, 10);
							if ((requested_index == 0) && (((void *)endpoint) == ((void *)&(recv_buff[6+22])))) {
								printf("Peer %s attempted to send a rejection message in response"
									" to the client sending a request for a metadata info piece but "
									"the response from the peer was ill-formed.\n", inet_ntoa((ptd->peer).sin_addr));
								resend_piece_request = 1;
							}
						}
					}
					else if (recv_buff[6+12]=='1') {
						// received metadata_info piece data
						printf("Received metadata info piece data from peer %s.\n",inet_ntoa((ptd->peer).sin_addr));
						char data_message[80] = {0};
						sprintf(data_message, 
								"d8:msg_typei1e5:piecei%de10:total_sizei%dee",
								 i,
								 mdi.metadata_size);
						if (strncmp(&(recv_buff[6]), data_message, strlen(data_message))==0) {
							// received data piece corresponding to request.
							memcpy(&(metadata[(16384*i)]), 
							       &(recv_buff[6+strlen(data_message)]),
							       payload_len-2-strlen(data_message));
							data_received = 1;
						}
					}
					
				}
				for (int i = 0; i<(recv_bytes - (4+payload_len)); ++i) {
					recv_buff[i] = recv_buff[(4+payload_len) + i];
				}
				recv_bytes -= (4+payload_len);
				if ((request_rejected == 1) || (resend_piece_request==1) || (data_received==1)) {
					break;
				}
			}
			if (request_rejected == 1) {
				break;
			}
			if (resend_piece_request == 1) {
				--i;
				continue;
			}
		}
		if (request_rejected == 1) {
			continue;
		}
		// we have the metadata_info inside the array metadata
		// check the metadata against the info-hash
		printf("Metadata info obtained from peer %s. Sizeof(unsigned long int):%lu\n", inet_ntoa((ptd->peer).sin_addr), sizeof(unsigned long int));
		unsigned char sha1_info_hash[20];
		extract_info_hash(ptd->magnet_link, sha1_info_hash);
		unsigned char *obtained_hash = compute_sha1_hash(metadata, mdi.metadata_size);	
		if (valid_metadata_hash(obtained_hash, sha1_info_hash)==1) {
			printf("Info hash downloaded matches sha1 hash in magnet link.\n");
			pthread_mutex_lock(ptd->metadata_info_dict_mutex);
                	if ((*(ptd->metadata_info_dictionary))==0) {
                        	*(ptd->metadata_info_dictionary) = metadata; 
                	}
                	pthread_mutex_unlock(ptd->metadata_info_dict_mutex);
			free(obtained_hash);
			break;
		}
		else {
			free(obtained_hash);
			printf("Info hash downloaded does not match the expected sha1 hash. Requesting the metadata info again.\n");
			continue;
		}
	}
	printf("Metadata info retrieved successfully.\n");
	pthread_mutex_lock(ptd->mi_data_mutex);

	if ( *(ptd->mi_data) == 0) {
		//struct containing metadata info in a friendly manor has not been
		//created. create it
		*(ptd->mi_data) = (struct metadata_file_info_dict *)malloc(sizeof(struct metadata_file_info_dict));
		struct metadata_file_info_dict *mi_data_ptr = *(ptd->mi_data);
		write(1, *(ptd->metadata_info_dictionary), mdi.metadata_size);
		if (fill_metadata_info_struct(*(ptd->metadata_info_dictionary), mi_data_ptr)==0) {
			printf("Metadata extracted from buffer into struct successfully.\n");
			pthread_mutex_unlock(ptd->mi_data_mutex);
			*(ptd->metadata_obtained) = 1;
			return 0;
		}
		else {
			printf("Metadata extraction from buffer failed. Thread terminating.\n");
			free(*(ptd->mi_data));
			*(ptd->mi_data) = 0;
			pthread_mutex_unlock(ptd->mi_data_mutex);
			return 0;
		}
	}
	pthread_mutex_unlock(ptd->mi_data_mutex);
	return 0;
	
		
}

// i1 and i2 are the addresses of two piece indices (0 starting).
// This function returns the address of the greater piece index
// or the null pointer if the two indices are the same
void *compare_index(void *i1, void *i2)
{
	unsigned int *index1 = (unsigned int *)i1;
	unsigned int *index2 = (unsigned int *)i2;
	if ((*index1) > (*index2)) {
		return i1;
	}
	else if ( (*index1) < (*index2) ) {
		return i2;
	}
	else {
		return 0;
	}
}

void print_index(void *index)
{
	unsigned int *index_ptr = (unsigned int *)index;
	printf("%u", *index_ptr);
}

void *compare_subpiece_index(void *i1, void *i2)
{
	unsigned int *index1 = (unsigned int *)i1;
        unsigned int *index2 = (unsigned int *)i2;
        if ((*index1) > (*index2)) {
                return i1;
        }
        else if ( (*index1) < (*index2) ) {
                return i2;
        }
        else {
                return 0;
        }
}

void print_subpiece_index(void *index)
{
	unsigned int *index_ptr = (unsigned int *)index;
        printf("%u", *index_ptr);
}

// Each thread is passed a pointer to an instance of this struct that they use during
// exchange of data with a specific peer.
struct data_transfer_per_thread_state
{
	char *magnet_link;
	unsigned int *total_pieces; // pointer to the number of total pieces in the download.
	struct sockaddr_in peer;
        unsigned char peer_id[20];
	struct client_per_peer_state cs;    // client state that the thread maintains and dynamically changes throughout data transfer
	int *init_piece_downloaded;  // points to an integer that is either 0 or 1, 0 if first piece has not been downloaded, otherwise 1 
	pthread_mutex_t *piece_index_mutex;
        int *current_piece_index;           // the current piece index we are downloading
        unsigned char *current_piece;       // array where we store the current piece

	struct metadata_file_info_dict *metadata_info_struct; // metadata information
	unsigned long int *total_download_size;
	unsigned int max_piece_index; // maximum possibly 0 starting piece index. Each piece is metadata_info_struct->piece_length longg
	                              // apart from the last piece in the file 
	struct binary_tree *peer_pieces; // keeps track of how many peers have particular pieces of the download
        pthread_mutex_t *peer_pieces_mutex; // mutex for accessing peer_pieces
	
	struct binary_tree *downloaded_pieces; // stores the zero starting indices that define piece indexes that we have successfully
	                                       // downloaded and checked that hash of
	pthread_mutex_t *downloaded_pieces_mutex; // mutex to synchronize acccess to downloaded_pieces binary tree.

	struct binary_tree **received_subpieces; // binary tree that stores unsinged integers defining the subpiece indices that we currently
	                                        // have
	pthread_mutex_t *received_subpieces_mutex; // mutex for thread synchronization of received_subpieces
	int *received_subpiece_count;
	pthread_mutex_t *received_subpiece_count_mutex; // counts the number of subpieces received. used for debugging

	struct binary_tree *have_piece_indices_sent; // Each thread has its own have_piece_indices_sent binary tree
						     // which stores integers stores the piece index's that have been sent to that threads 
						     // peer through have messages after the piece has been fully downloaded.
	int *have_piece_index;          // points to the current piece index that we are sending to peers through have messages
	                                // It is the last current_piece_index that was successfully downloaded
	int *send_have_messages; // points to an integer that is 0 to disable sending of have messages to peers (it is only 0 before
                                 // we have successfully downloaded any pieces and thus have no piece indexes to send), otherwise it has
				 // a value of 1 which enables sending oh have messages	
	char switch_client_to_peer_choke_status; // 0 indicates to remain the same. 1 indicates for the client thread to send an unchoke/choke message
	                               // to it's peer that changes the choke status of data transfer from client to peer.
	pthread_mutex_t switch_client_to_peer_choke_status_mutex;	
	
	unsigned int *manage_interested_peer_choking;  // pointer to an integer that is 0 if the master thread does not need to manage 
	                                              // which peers are unchoked, otherwise is 1
	pthread_mutex_t *manage_interested_peer_choking_mutex;
	int *optimistic_unchoke_peer_index; // defines the 0 starting index of the peer that is currently being optimistically unchoked
	                                    // has a value of -1 initially when there are no optimistically unchoked peers
	unsigned char optimistic_unchoke_availability; // per thread data 0 if the thread isnt a candiatate for optimistic unchoke,
						       // otherwise 1
	
};

// This function places in the preallocated buffer buff the data defined by
// metadata_info_struct and the remaining parameters. Note that this function
// assumes that buff is big enough to hold length number of bytes and that the
// data has already been downloaded in the relevant file(s). Returns 0 on success, 1 on failure
int extract_downloaded_data(unsigned char *buff, 
		             struct metadata_file_info_dict *metadata_info_struct,
			     unsigned int piece_index,
			     unsigned int offset,
  		             unsigned int length)
{
	if ((metadata_info_struct->length) > 0) {
		// Download consists of one file only
		char path[3000] = {0};
                sprintf(path, "%s/Downloads/%s", getenv("HOME"), metadata_info_struct->name);
		FILE *fp = fopen(path, "r");
		if (fp==NULL) {
			printf("Error opening file to transfer part of it to a peer. %s.\n", strerror(errno));
			return 1;
		}
		long file_offset = piece_index*(metadata_info_struct->piece_length) + offset;		
		if (fseek(fp, file_offset, SEEK_SET)==-1) {
			printf("Error seeking to a location in the file to read data and send it to a peer.\n");
			return 1;
		}
		if (fread(buff, 1, length, fp) != length) {
			printf("Error reading data from file to send to peer.\n");
			return 1;
		}
		return 0;
	}
	else {
		// Download consists of multiple files
		unsigned long int request_lower_index = piece_index*(metadata_info_struct->piece_length) + offset;
		unsigned long int request_upper_index = request_lower_index + length - 1;
		unsigned long int curr_lower_index = 0;
		unsigned long int curr_upper_index = 0;
		int pos = 0;
		unsigned char requested_lower_index_passed = 0;
		struct doubly_linked_list *files = metadata_info_struct->files;
		struct link *curr_link = dlist_beg(files);
		while (curr_link != dlist_end(files)) {
			if (curr_upper_index != 0) {
				curr_lower_index = curr_upper_index + 1;
			}
			struct file *f = (struct file *)dlist_get_val(curr_link);
			if (curr_upper_index == 0) {
				curr_upper_index = f->length - 1;
			}
			else {
				curr_upper_index += f->length;
			}
			if ((requested_lower_index_passed == 0) &&
		            (curr_upper_index >= request_lower_index)) {
				requested_lower_index_passed = 1;
				char path[3000];
				sprintf(path, "%s/Downloads/%s/%s", getenv("HOME"), metadata_info_struct->name, f->path);
				FILE *fp = fopen(path, "r");
				if (fp==NULL) {
					printf("Error opening file %s to read from and send peer piece.\n", path);
					return 1;
				}
				if (fseek(fp,request_lower_index - curr_lower_index, SEEK_SET)==-1) {
					printf("Error seeking to downloaded file position to read and send to peer.\n");
					return 1;
				}
				if (curr_upper_index < request_upper_index) {
					size_t bytes_read = fread(&(buff[pos]), 1, f->length - (request_lower_index-curr_lower_index), fp);
					if (bytes_read != (f->length - (request_lower_index-curr_lower_index))) {
						printf("Error reading part of download from disk to send to peer.\n");
						return 1;
					}
					pos += bytes_read;
				}
				else {
					// The whole request is from the current file f
					size_t bytes_read = fread(&(buff[pos]), 1, length, fp);
					if (bytes_read != length) {
						printf("Error reading from file %s to send data to peer.\n", f->path);
						return 1;
					}
					return 0;
				}	
			}
			else if (requested_lower_index_passed == 1) {
				char path[3000];
                                sprintf(path, "%s/Downloads/%s/%s", getenv("HOME"), metadata_info_struct->name, f->path);
                                FILE *fp = fopen(path, "r");
				if (fp==NULL) {
                                        printf("Error opening file %s to read from and send peer piece.\n", path);
                                        return 1;
                                }
				if (curr_upper_index < request_upper_index) {
					//copy the whole file to buff
					size_t bytes_read = fread(&(buff[pos]), 1, f->length, fp);
					if (bytes_read != (f->length)) {
						printf("Error reading file %s to send to peer.\n", path);
						return 1;
					}
					pos += bytes_read;
				}
				else {
					// copy part (or all) of this file to buff
					size_t bytes_read = fread(&(buff[pos]), 1, request_upper_index - curr_lower_index + 1, fp);
					if (bytes_read != (request_upper_index - curr_lower_index + 1)) {
						return 1;
					}
					return 0;
				}
				
			}
			curr_link = dlist_succ(curr_link);
		}	
	}

}

// function returns 0 if the first 20 bytes of buff1 and buff2 match,
// otherwise returns 1.
int check_sha1_hash_match(unsigned char *buff1,
                     unsigned char *buff2)
{
	int retval = 0;
	for (int i=0; i<20; ++i) {
		if (buff1[i] != buff2[i]) {
			retval = 1;
		}
	}
	return retval;
}

// writes the piece in current_piece to into the corrosponding files
// specified in metadata_info_strct. current_piece is the piece with index piece_index
// in the download of length piece_len bytes. piece_len != metadata_info_struct->piece_length only if
// piece_index is the last piece of the download.
// Function returns 0 in success, 1 on failure
int write_data_to_files(unsigned char *current_piece,
		   unsigned int piece_len,
		   struct metadata_file_info_dict *metadata_info_struct,
		   unsigned int piece_index)
{

	unsigned long int beg_offset = piece_index*(metadata_info_struct->piece_length); // 0 starting pos of current_piece amongst the files
	unsigned long int end_offset = beg_offset + piece_len - 1; // finishing 0 starting pos of current_piece within the files
	if ((metadata_info_struct->length) > 0) {
		// We are downloading only one file
		char path[2000] = {0};
                sprintf(path, "%s/Downloads/%s", getenv("HOME"), metadata_info_struct->name);
		FILE *fp = fopen(path, "r+"); // open file for both reading and writing
		if (!fp) {
			printf("Error opening file %s to write downloaded data to disk.\n",path);
			return 1;
		}
		if (fseek(fp, beg_offset, SEEK_SET)==-1) {
			printf("Error seeking to a position in file %s to write data to.\n", path);
			return 1;
		}
		if (fwrite(current_piece, 1, piece_len, fp)!= piece_len) {
			printf("Error writing data to disk (file %s).\n", path);
			return 1;
		}
		if (fclose(fp)== EOF) {
			printf("Error closing file %s after writing data to it.\n", path);
			return 1;
		}
		return 0;
	}
	unsigned long int curr_lower_pos = 0; // 0 starting position of the first byte of the current file within the full download 
	unsigned long int curr_upper_pos = 0; // 0 starting positon of the last byte of the current file within the full download
	unsigned int cp_pos = 0; // current_piece position (0 starting)
	struct doubly_linked_list *files = metadata_info_struct->files;
	struct link *curr_link = dlist_beg(files);
	unsigned char started_writing_data = 0;
	while (curr_link != dlist_end(files)) {
		struct file *f = (struct file *)dlist_get_val(curr_link);
		/*if (curr_lower_pos != 0) {
			curr_lower_pos = curr_upper_pos + 1;
		}*/
		if (curr_upper_pos != 0) {
			curr_upper_pos += (f->length);
		}
		else {
			curr_upper_pos = (f->length) - 1;
		}
		if ((beg_offset >= curr_lower_pos) && (beg_offset <= curr_upper_pos)) {
			// current_piece starts in this file
			char path[3000] = {0};
	                sprintf(path, "%s/Downloads/%s/%s", getenv("HOME"), metadata_info_struct->name, f->path);	
			FILE *fp = fopen(path, "r+");
			if (fp==NULL) {
				printf("Error opening file %s with the intention of writing data to it.\n", path);
				return 1;
			}	
			if (fseek(fp, beg_offset - curr_lower_pos, SEEK_SET)==-1) {
				printf("Error seeking to file position to write data at that position (file %s).\n", path);
				return 1;
			}
			if (end_offset <= curr_upper_pos) {
				// whole piece is contained within this one file
				if (fwrite(current_piece, 1, piece_len, fp)!=piece_len) {
					printf("Error writing downloaded data to file %s.\n", path);
					return 1;
				}
				if (fclose(fp)==EOF) {
					printf("Error closing fifle %s.\n", path);
				}	
				return 0;
			}
			else {
				//unsigned long int write_len = (f->length) - (beg_offset - curr_lower_pos + 1);
				printf("beg_offset:%lu   end_offset:%lu   curr_lower_pos:%lu   curr_upper_pos:%lu  f->length:%lu\n",
					beg_offset, end_offset, curr_lower_pos, curr_upper_pos, f->length);
				unsigned long int write_len = (f->length) - (beg_offset - curr_lower_pos);
				size_t res = fwrite(current_piece, 1, write_len, fp);
				printf("res:%lu  write_len:%lu\n", res, write_len);
				if (res != write_len) {
					printf("Error writing downloaded piece to disk in file %s.\n", path);
					return 1;
				}
				cp_pos = write_len;
				started_writing_data = 1;
			}
		}
		else if (end_offset <= curr_upper_pos) {
			// current_piece ends in this file
			char path[3000] = {0};
			sprintf(path, "%s/Downloads/%s/%s", getenv("HOME"), metadata_info_struct->name, f->path);
                        FILE *fp = fopen(path, "r+");		
			if (fp == NULL) {
				printf("Error opening file %s to write data to on disk.\n", path);
				return 1;
			}	
			unsigned int write_len = piece_len - cp_pos;
			if (fwrite(&(current_piece[cp_pos]), 1, write_len, fp) != write_len) {
				printf("Error writing data to file %s on disk.\n", path);
			        return 1;	
			}
			if (fclose(fp)==EOF) {
				printf("Error closing file %s after writing.\n", path);
				return 1;
			}
			return 0;
		}
		else if ((started_writing_data) && (end_offset > curr_upper_pos)) {
			printf("beg_offset:%lu end_offset:%lu  curr_lower_pos:%lu curr_upper_pos:%lu\n", beg_offset, end_offset, curr_lower_pos, curr_upper_pos);
			// end_offet > curr_upper_pos so our piece covers all of the current file
			char path[3000] = {0};
			sprintf(path, "%s/Downloads/%s/%s", getenv("HOME"), metadata_info_struct->name, f->path);
                        FILE *fp = fopen(path, "r+");
			if (fp == NULL) {
                                printf("Error opening file %s to write data to on disk.\n", path);
                                return 1;
                        }
			size_t res = fwrite(&(current_piece[cp_pos]), 1, f->length, fp);
			printf("\nfwrite res:%u  f->length:%lu  file:%s\n",res, f->length, f->path);
			if (res != (f->length)) {
				printf("Error writing downloaded data to disk on file %s.\n", path);
				return 1;
			}
			if (fclose(fp)==EOF) {
				printf("Error closing file %s after writing data to it.\n", path);
				return 1;	
			}
			cp_pos += f->length;
		}
		curr_lower_pos += (f->length);
		curr_link = dlist_succ(curr_link);
	}	

}

// Send a subpiece request, assume that the thread already has all of the locks needed
// requires ptd->received_subpieces_mutex and ptd->piece_index_mutex to be locked on entry.
// Inserts request into clients per peer request_times binary_tree
void send_subpiece_request(int client_socket_fd, struct data_transfer_per_thread_state *ptd)
{
	unsigned int current_piece_length = (ptd->metadata_info_struct)->piece_length;
	unsigned int max_piece_index = (*(ptd->total_download_size))/current_piece_length;
	if ( ((*(ptd->total_download_size)) % current_piece_length) == 0) {
		--max_piece_index;
	}
	unsigned int max_subpiece_index = current_piece_length / 16384;
	if ((current_piece_length % 16384) == 0) {
		--max_subpiece_index;
	}
	unsigned int final_piece_length = 0;
	if ((*(ptd->current_piece_index)) == max_piece_index) {
		final_piece_length = (*(ptd->total_download_size)) % current_piece_length;
		if (final_piece_length == 0) {
			final_piece_length = current_piece_length;
		}
		max_subpiece_index = final_piece_length / 16384;
		if ((final_piece_length % 16384)==0) {
			--max_subpiece_index;
		}
	}
	unsigned int subpiece_index_to_request = rand() % (max_subpiece_index + 1);
	while (btree_search(*(ptd->received_subpieces), &subpiece_index_to_request)==1) {
		subpiece_index_to_request = rand() % (max_subpiece_index + 1);
	}
	unsigned int piece_index_request = *(ptd->current_piece_index);
	unsigned int offset_request = subpiece_index_to_request*16384;
	unsigned int length_request = 16384;
	if (subpiece_index_to_request == max_subpiece_index) {
		length_request = current_piece_length % 16384;
		if (length_request == 0) {
			length_request = 16384;
		}
		if ((*(ptd->current_piece_index)) == max_piece_index) {
			length_request = final_piece_length % 16384;
			if (length_request == 0) {
				length_request = 16384;
			}
		}
	}
	unsigned char *subpiece_request = (unsigned char *)malloc(17);
	memset(subpiece_request, 0, 3);
	subpiece_request[3] = 13;
	subpiece_request[4] = 6;
	unsigned int *piece_index_request_ptr = (unsigned int *)&(subpiece_request[5]);
	*piece_index_request_ptr = htonl(piece_index_request);
	unsigned int *offset_request_ptr = (unsigned int *)&(subpiece_request[9]);
	*offset_request_ptr = htonl(offset_request);
	unsigned int *length_request_ptr = (unsigned int *)&(subpiece_request[13]);
	*length_request_ptr = htonl(length_request);
	ssize_t sent_bytes = send(client_socket_fd, subpiece_request, 17, 0);
	if (sent_bytes != 17) {
		printf("sent_bytes: %d\n", sent_bytes);
		printf("Error sending piece request to peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
	}
	struct request_timestamp rt;
	rt.request.piece_index = piece_index_request;
	rt.request.begin = offset_request;
	rt.request.length = length_request;
	rt.timestamp = time(NULL);
	btree_insert((ptd->cs).request_times, &rt);
}

void *perform_data_exchange(void *per_thread_data)
{
	struct data_transfer_per_thread_state *ptd = (struct data_transfer_per_thread_state *)per_thread_data;
	
	unsigned char recv_buff[20000];

        char *bittorrent_header_text = "BitTorrent protocol";
        struct bittorrent_main_handshake bmh;
        bmh.len_19_prefix = 19;
        memcpy(bmh.bittorrent_protocol, bittorrent_header_text, 19);
        memset(bmh.reserved_bytes, 0, 8);
        extract_info_hash(ptd->magnet_link, bmh.sha1_info_hash);
        memcpy(bmh.peer_id, ptd->peer_id, 20);

	int client_socket_fd = socket(AF_INET, SOCK_STREAM, 6); // TCP socket
        if (client_socket_fd == -1) {
                printf("Error obtaining tcp/ip socket client endpoint.\n");
        }

        socklen_t sock_len = sizeof(struct sockaddr);
        if (connect(client_socket_fd, (struct sockaddr *)&(ptd->peer), sock_len)!= 0) {
                printf("Error connecting to peer through tcp/ip. %s\n", strerror(errno));
                close(client_socket_fd);
                return 0;
        }
        ssize_t sent_bytes = send(client_socket_fd, &bmh, sizeof(struct bittorrent_main_handshake), 0);
        if (sent_bytes != sizeof(struct bittorrent_main_handshake)) {
                printf("Error sending bittorrent main handshake, only sent %d bytes.\n", sent_bytes);
                close(client_socket_fd);
                return 0;
        }

        struct bittorrent_main_handshake *bmh_peer = (struct bittorrent_main_handshake *)recv_buff;
        ssize_t recv_bytes = 0;
        while (recv_bytes < sizeof(struct bittorrent_main_handshake)) {
                ssize_t new_bytes = recv(client_socket_fd, &(recv_buff[recv_bytes]), 20000 - recv_bytes, 0);
                if (new_bytes == -1) {
                        printf("Error receiving bittorrent main handshake from peer. Thread terminating.\n");
                        close(client_socket_fd);
                        return 0;
                }
                else if (new_bytes == 0) {
                        close(client_socket_fd);
                        return 0; // peer closed connection
                }
                else {
                        recv_bytes += new_bytes;
                }
        }
	if (check_peer_handshake2(bmh.sha1_info_hash, bmh_peer)!=0) {
                printf("Bittorrent main handshake sent from peer invalid.\n");
                close(client_socket_fd);
                return 0;
        }
        printf("Successful handshake received from peer %s!\n", inet_ntoa((ptd->peer).sin_addr));
        int bmh_len = (int)sizeof(struct bittorrent_main_handshake);
        for (int i = 0; i<(recv_bytes - bmh_len); ++i) {
                recv_buff[i] = recv_buff[bmh_len + i];
        }
        recv_bytes -= bmh_len;
        unsigned int payload_len = 0;
	unsigned char keep_alive[4] = {0x00, 0x00, 0x00, 0x00};
	unsigned char choke_msg[5] = {0x00, 0x00, 0x00, 0x01, 0x00};
	unsigned char unchoke_msg[5] = {0x00, 0x00, 0x00, 0x01, 0x01};
	unsigned char interested_msg[5] = {0x00, 0x00, 0x00, 0x01, 0x02};
	unsigned char not_interested_msg[5] = {0x00, 0x00, 0x00, 0x01, 0x03};
	time_t base_time = time(NULL);
	unsigned char first_message = 1; // indicator used in determining whether a bitfield message should be sent
	while (1) {
		if (first_message) {
			ptd->optimistic_unchoke_availability = 1;
		}
		pthread_mutex_lock(ptd->downloaded_pieces_mutex);
		if ((first_message == 1) && (btree_no_of_nodes(ptd->downloaded_pieces)>0)) {
			// bitfield message required to be sent to peer
			int no_of_nodes = btree_no_of_nodes(ptd->downloaded_pieces);
			unsigned int max_piece_index = *((unsigned int *)btree_get(ptd->downloaded_pieces, no_of_nodes-1));
			unsigned int bitfield_length = (max_piece_index/8) + 1;
			unsigned char *bitfield_msg = (unsigned char *)malloc(bitfield_length + 5);
			unsigned int *payload_len_ptr = (unsigned int *)bitfield_msg;		
			*payload_len_ptr = htonl(bitfield_length + 1);
			bitfield_msg[4] = 5; // bitfield message indicator
			memset(&(bitfield_msg[5]), 0, bitfield_length);
			for (int i=0; i<bitfield_length; ++i) {
				for (int j=0; j<8; ++j) {
					unsigned int curr_piece_index = (i*8) + j;
					if (btree_search(ptd->downloaded_pieces, &curr_piece_index)==1) {
						unsigned char bitmask = 128 >> j;
						bitfield_msg[5+i] |= bitmask;
					}
				}
			}
			if (send(client_socket_fd, bitfield_msg, bitfield_length + 5, 0)!= (bitfield_length+5)) {
				printf("Error sending bitfield message to peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
			}
			else {
				printf("Successfully sent bitfield message to peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
			}
			free(bitfield_msg);
		}
		if (first_message) {
			if (send(client_socket_fd, interested_msg, 5, 0)!= 5) {
				printf("Error sending initial interested message to peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
			}
			else {
				(ptd->cs).client_interested = 1;
			}
		}
		first_message = 0;
		pthread_mutex_unlock(ptd->downloaded_pieces_mutex);
		pthread_mutex_lock(&(ptd->switch_client_to_peer_choke_status_mutex));
                if ((ptd->switch_client_to_peer_choke_status) == 1) {
                        if ((ptd->cs).client_to_peer_choke_status == 1) {
                                // switch client to peer choke status to unchoke (0)
                                if (send(client_socket_fd, unchoke_msg, 5, 0)!= 5) {
                                        printf("Error sending unchoke message to peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
                                }
                                else {
                                        (ptd->cs).client_to_peer_choke_status = 0;
					printf("Unchoked peer %s\n", inet_ntoa((ptd->peer).sin_addr));
                                }
                        }
                        else if ((ptd->cs).client_to_peer_choke_status == 0) {
                                // switch client to peer choke status to choked (1)
                                if (send(client_socket_fd, choke_msg, 5, 0)!= 5) {
                                        printf("Error sending choke message to peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
                                }
                                else {
                                        (ptd->cs).client_to_peer_choke_status = 1;
					printf("Choked peer %s\n", inet_ntoa((ptd->peer).sin_addr));
                                }
                        }
                        ptd->switch_client_to_peer_choke_status = 0;
                }
                pthread_mutex_unlock(&(ptd->switch_client_to_peer_choke_status_mutex));
		if ((*(ptd->send_have_messages) == 1) && 
		    (btree_search(ptd->have_piece_indices_sent, ptd->have_piece_index)==0)) {
			unsigned int have_piece_index = (unsigned int)(*(ptd->have_piece_index));
			unsigned char have_msg[9] = {0, 0, 0, 5, 4, 0, 0, 0, 0};
			unsigned int *have_piece_index_ptr = (unsigned int *)&(have_msg[5]);
			*have_piece_index_ptr = htonl(have_piece_index);
			if (send(client_socket_fd, have_msg, 9, 0)!=9) {
				printf("Error sending have message to peer %s indicating that we have received peice %d.\n",
					inet_ntoa((ptd->peer).sin_addr), have_piece_index);
			}
			btree_insert(ptd->have_piece_indices_sent, &have_piece_index);
		}

		pthread_mutex_lock(ptd->piece_index_mutex);
		if (*(ptd->init_piece_downloaded) == 0) {
			time_t curr_time = time(NULL);
			double interval = difftime(curr_time, base_time);
			if (interval > 120.0) {
				// 120 seconds has passed without us downloading the first piece. Try downloading another piece
				// at random.
				pthread_mutex_lock(ptd->peer_pieces_mutex);
				pthread_mutex_lock(ptd->received_subpieces_mutex);
				int index = rand() % btree_no_of_nodes(ptd->peer_pieces);
				struct peers_piece *p = (struct peers_piece *)btree_get(ptd->peer_pieces, index);
				*(ptd->current_piece_index) = p->piece_index;
				base_time = time(NULL);
				free_btree(*(ptd->received_subpieces));
				*(ptd->received_subpieces) = init_btree(sizeof(unsigned int), compare_subpiece_index, print_subpiece_index);
				pthread_mutex_unlock(ptd->received_subpieces_mutex);
				pthread_mutex_unlock(ptd->peer_pieces_mutex);
			}
		}
		pthread_mutex_unlock(ptd->piece_index_mutex);
		unsigned char continue_loop = 0;
		while (recv_bytes < 4) {
			struct timeval tv;
			tv.tv_sec = 30;
			tv.tv_usec = 0;
			fd_set read_fds;
			FD_ZERO(&read_fds);
			FD_SET(client_socket_fd, &read_fds);
			int select_res = select(client_socket_fd+1, &read_fds, NULL, NULL, &tv);
			if (select_res == 0) {
				// 30 second timeout occurred, send keep alive message
				if (send(client_socket_fd, keep_alive, 4, 0)!= 4) {
					printf("Error sending keep alive message to peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
				}	
				printf("Sent keep alive message to peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
				continue_loop = 1;
				break;
			}
			else if (select_res == -1) {
				printf("Error occurred (in select call) whilst waiting to receive message length from peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
				continue;
			}
			ssize_t new_bytes = recv(client_socket_fd, &(recv_buff[recv_bytes]), 20000 - recv_bytes, 0);
                	if (new_bytes == -1) {
                	        printf("Error receiving payload message length from peer. Thread terminating.\n");
                	        close(client_socket_fd);
                	        return 0;
               	 	}
                	else if (new_bytes == 0) {
				printf("recv returned 0 bytes instead of payload length. Thread and connection terminating.\n");
                	        close(client_socket_fd);
                	        return 0; // peer closed connection
               	 	}
                	else {
                	        recv_bytes += new_bytes;
                	}
		}
		if (continue_loop==1) {
			continue;
		}
		unsigned int *payload_len_ptr = (unsigned int *)recv_buff;
		unsigned int payload_len = ntohl(*payload_len_ptr);
		while (recv_bytes < (4+payload_len)) {
			struct timeval tv;
                        tv.tv_sec = 30;
                        tv.tv_usec = 0;
                        fd_set read_fds;
                        FD_ZERO(&read_fds);
                        FD_SET(client_socket_fd, &read_fds);
                        int select_res = select(client_socket_fd+1, &read_fds, NULL, NULL, &tv);
                        if (select_res == 0) {
                                // 30 second timeout occurred, send keep alive message
                                if (send(client_socket_fd, keep_alive, 4, 0)!= 4) {
                                        printf("Error sending keep alive message to peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
                                        continue;
                                }
                                printf("Sent keep alive message to peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
                                continue;
                        }
                        else if (select_res == -1) {
                                printf("Error occurred (in select call) whilst waiting to receive data from peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
                                continue;
                        }
			ssize_t new_bytes = recv(client_socket_fd, &(recv_buff[recv_bytes]), 20000 - recv_bytes, 0);
                        if (new_bytes == -1) {
                                printf("Error receiving message from peer %s. Thread terminating.\n", inet_ntoa((ptd->peer).sin_addr));
                                close(client_socket_fd);
                                return 0;
                        }
                        else if (new_bytes == 0) {
				printf("recv returned 0 bytes instead of data. Thread and connection terminating.\n");
                                close(client_socket_fd);
                                return 0; // peer closed connection
                        }
                        else {
                                recv_bytes += new_bytes;
			}
		}
		if (payload_len == 0) {
			// client received keep alive message
			for (int i=0; i<(recv_bytes-4); ++i) {
				recv_buff[i] = recv_buff[4+i];
			}
			recv_bytes -= 4;
			continue;
		}
		else {
			// We have a message to process
			if (payload_len == 1) {
				if (recv_buff[4] == 0) {
					// client received a choke message from peer
					(ptd->cs).peer_to_client_choke_status = 1;
					printf("Choke message received from peer %s\n", 
                                                inet_ntoa((ptd->peer).sin_addr));
					/*if ((ptd->cs).client_interested == 1) {
						if (send(client_socket_fd, not_interested_msg, 5, 0)!=5) {
							printf("Error sending peer %s a not interested message.\n",
							       inet_ntoa((ptd->peer).sin_addr));
						}
						(ptd->cs).client_interested = 0;
					}*/
				}
				else if (recv_buff[4] == 1) {
					// peer to client data transfer is unchoked (client received unchoke message from peer)
					printf("Client has received unchoke message from peer %s.\n",inet_ntoa((ptd->peer).sin_addr));
					(ptd->cs).peer_to_client_choke_status = 0;
					if ((ptd->cs).client_interested == 0) {
						if (send(client_socket_fd, interested_msg, 5, 0)!=5) {
							printf("Error sending peer %s an interested message.\n", inet_ntoa((ptd->peer).sin_addr));
						}
						else {
							(ptd->cs).client_interested = 1;
						}
					}
					if ((ptd->cs).client_interested) {
						pthread_mutex_lock(ptd->piece_index_mutex);
						int curr_piece_index = *(ptd->current_piece_index);
						if ((curr_piece_index != -1) && ((ptd->cs).bitfield_length > (curr_piece_index/8))) {
							unsigned int bitfield_index = curr_piece_index / 8;
							unsigned char mask = 128 >> (curr_piece_index % 8);
							if ( (((ptd->cs).bitfield)[bitfield_index] & mask) != 0) {
								// peer has the piece that we are currently downloading
								pthread_mutex_lock(ptd->received_subpieces_mutex);
								send_subpiece_request(client_socket_fd, ptd);
								pthread_mutex_unlock(ptd->received_subpieces_mutex);
							}
						}
						pthread_mutex_unlock(ptd->piece_index_mutex);
					}
					   
				}
				else if (recv_buff[4] == 2) {
					// peer is interested in reeceiving data from the client
					char signal_master_thread = 0; // signal master thread to manage whos unchoked
					printf("Client received interested message from peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
					if (((ptd->cs).client_to_peer_choke_status == 0) &&
					    ((ptd->cs).peer_interested == 0)) {
						signal_master_thread = 1;
					}
					(ptd->cs).peer_interested = 1;
					if (signal_master_thread) {
						pthread_mutex_lock(ptd->manage_interested_peer_choking_mutex);
						*(ptd->manage_interested_peer_choking) = 1;		
						pthread_mutex_unlock(ptd->manage_interested_peer_choking_mutex);		
					}	
				}
				else if (recv_buff[4] == 3) {
					// peer is not interested in receiving data from client 
					printf("Client received not interested message from peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
					(ptd->cs).peer_interested = 0;
				}
				else {
					printf("Error. Client receivied unsupported message.\n");
				}
			}
			else if (recv_buff[4] == 4) {
				// client received have message
				printf("Client received have message from peer %s.\n",inet_ntoa((ptd->peer).sin_addr));
				unsigned int *piece_index_ptr = (unsigned int *)(&(recv_buff[5]));
				unsigned int piece_index = ntohl(*piece_index_ptr);
				unsigned int bitfield_index = piece_index / 8;
				if ((ptd->cs).bitfield_length <= bitfield_index) {
					unsigned char *temp_bitfield = (unsigned char *)malloc(bitfield_index+1);
					memset(temp_bitfield, 0, bitfield_index+1);
					for (int i=0; i<((ptd->cs).bitfield_length); ++i) {
						temp_bitfield[i] = ((ptd->cs).bitfield)[i];
					}
					if ((ptd->cs).bitfield != 0 ) {
						free((ptd->cs).bitfield);
					}
					(ptd->cs).bitfield = temp_bitfield;
					(ptd->cs).bitfield_length = bitfield_index + 1;
				}
				unsigned char mask = 128 >> (piece_index % 8);
				(ptd->cs).bitfield[bitfield_index] |= mask;
				struct peers_piece p;
				p.piece_index = piece_index;
				p.count = 1;
				pthread_mutex_lock(ptd->piece_index_mutex);
				pthread_mutex_lock(ptd->peer_pieces_mutex);
				if (btree_search(ptd->peer_pieces, &p)==1) {
					struct peers_piece *p1 = btree_find(ptd->peer_pieces, &p);
					++(p1->count);
				}
				else {
					btree_insert(ptd->peer_pieces, &p);
				}
				if (*(ptd->current_piece_index) == -1) {
					*(ptd->current_piece_index) = piece_index;
					base_time = time(NULL);
				}
				pthread_mutex_unlock(ptd->peer_pieces_mutex);
				pthread_mutex_unlock(ptd->piece_index_mutex);
			}
			else if (recv_buff[4] == 5) {
				// client received bitfield message. Guaranteed to be sent as the first bittorrent message after the handshake
				// or no bitfield message will be received at all
				printf("Client has received bitfield message from peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
				(ptd->cs).bitfield = (unsigned char *)malloc(payload_len-1);
				(ptd->cs).bitfield_length = payload_len-1;
				memcpy((ptd->cs).bitfield, &(recv_buff[5]), payload_len-1);
				for (int i=0; i<(ptd->cs).bitfield_length; ++i) {
					for (int j=0; j<8; ++j) {
						unsigned char mask = 128 >> j;
						if ( ((((ptd->cs).bitfield)[i]) & mask) != 0) {
							struct peers_piece p;
							p.piece_index = i*8 + j;
							p.count = 1;
							pthread_mutex_lock(ptd->piece_index_mutex);
							if (*(ptd->current_piece_index) == -1) {
                                        			*(ptd->current_piece_index) = p.piece_index;
                                        			base_time = time(NULL);
                                			}
							pthread_mutex_unlock(ptd->piece_index_mutex);
							pthread_mutex_lock(ptd->peer_pieces_mutex);
							if (btree_search(ptd->peer_pieces, &p)==1) {
								struct peers_piece *p1 = btree_find(ptd->peer_pieces, &p);
                                        			++(p1->count);
							}
							else {
								btree_insert(ptd->peer_pieces, &p);
							}
							pthread_mutex_unlock(ptd->peer_pieces_mutex);
						}
					}
				}
			}
			else if (recv_buff[4] == 6) {
				// client has received request message
				printf("Client has received request message from peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
				unsigned int *requested_piece_index_ptr = (unsigned int *)(&(recv_buff[5]));
				unsigned int *requested_offset_ptr = (unsigned int *)(&(recv_buff[9]));
				unsigned int *requested_length_ptr = (unsigned int *)(&(recv_buff[13]));
				unsigned int requested_piece_index = ntohl(*requested_piece_index_ptr);
				unsigned int requested_offset = ntohl(*requested_offset_ptr);
				unsigned int requested_length = ntohl(*requested_length_ptr);
				if (requested_length > 16384) {
					printf("Peer %s requested over 16384 bytes of data in a single request. Terminating connection to"
						" the peer.\n", inet_ntoa((ptd->peer).sin_addr));
						
					close(client_socket_fd);
					return 0; 
				}
				unsigned char store_request = 1;

				pthread_mutex_lock(ptd->downloaded_pieces_mutex);
				if ( (btree_search(ptd->downloaded_pieces, &requested_piece_index)==1) &&
			             (((ptd->cs).client_to_peer_choke_status)== 0) &&
			             (((ptd->cs).peer_interested)==1) )	   {
					printf("sending subpiece to peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
					// client has data peer is requesting. Send the peer the data it requested in a piece message
					store_request = 0;
					unsigned int buff_len = 0;
					unsigned char *piece_msg = (unsigned char *)malloc(13 + requested_length);
					unsigned int *payload_len_ptr = (unsigned int *)piece_msg;
					*payload_len_ptr = htonl(requested_length + 9);
					piece_msg[4] = 7; // piece message indicator
					unsigned int *piece_index_ptr = (unsigned int *)(&(piece_msg[5]));
					*piece_index_ptr = htonl(requested_piece_index);
					unsigned int *offset_ptr = (unsigned int *)(&(piece_msg[9]));
					*offset_ptr = htonl(requested_offset);	
					extract_downloaded_data(&(piece_msg[13]),
							        ptd->metadata_info_struct, 
								requested_piece_index,
							  	requested_offset,
				 				requested_length);
					ssize_t sent_bytes = send(client_socket_fd, piece_msg, requested_length + 13,0);
					if (sent_bytes != (requested_length + 13)) {
						// Error sending piece message in response to peer request
						printf("Error sending peer piece message. Storing the peers request.\n");
						store_request = 1;
					}
					free(piece_msg);
				}
				pthread_mutex_unlock(ptd->downloaded_pieces_mutex);
				if (store_request) {
					struct request r;
					r.piece_index = requested_piece_index;
					r.begin = requested_offset;
					r.length = requested_length;
					dlist_push_back((ptd->cs).requests, &r);	
				}
			}
			else if (recv_buff[4] == 7) {
				// client received subpiece
				unsigned int *received_piece_index_ptr = (unsigned int *)(&(recv_buff[5]));
				unsigned int received_piece_index = ntohl(*received_piece_index_ptr);
				unsigned int *received_offset_ptr = (unsigned int *)(&(recv_buff[9]));
				unsigned int received_offset = ntohl(*received_offset_ptr);
				pthread_mutex_lock(ptd->piece_index_mutex);
				if (received_piece_index == (*(ptd->current_piece_index))) {
					unsigned int received_subpiece_index = received_offset / 16384;
					if ((received_offset % 16384) != 0) {
						printf("Error in a received piece message from peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
					}
					else {
						unsigned int subpiece_length = payload_len - 9;
						unsigned int end_piece_length = (*(ptd->total_download_size)) % ((ptd->metadata_info_struct)->piece_length);
						if (end_piece_length == 0) {
							end_piece_length = (ptd->metadata_info_struct)->piece_length;
						}
						unsigned int end_subpiece_length = end_piece_length % 16384;
						if (end_subpiece_length==0) {
							end_subpiece_length = 16384;
						}
						unsigned int eofpiece_subpiece_length = (ptd->metadata_info_struct)->piece_length % 16384;
						if (((ptd->metadata_info_struct)->piece_length % 16384)==0) {
							eofpiece_subpiece_length = 16384;
						}
						if ((subpiece_length != 16384) && (subpiece_length != end_subpiece_length) &&
						    (subpiece_length != eofpiece_subpiece_length)) {
							printf("Error in the length of the piece message received from peer %s.\n",
									 inet_ntoa((ptd->peer).sin_addr));
						}
						else {
							pthread_mutex_lock(ptd->received_subpieces_mutex);
							if (btree_search(*(ptd->received_subpieces), &received_subpiece_index)==0) {
								// new subpiece received. add it to ptd->received_subpieces
								memcpy(&((ptd->current_piece)[received_offset]), &(recv_buff[13]), 
								       subpiece_length);
								
								int no_of_nodes_before_insert = btree_no_of_nodes(*(ptd->received_subpieces));
								btree_insert(*(ptd->received_subpieces), &received_subpiece_index);
								int no_of_nodes_after_insert = btree_no_of_nodes(*(ptd->received_subpieces));
								struct request_timestamp rt;
								rt.request.piece_index = received_piece_index;
								rt.request.begin = received_offset;
								rt.request.length = subpiece_length;
								rt.timestamp = time(NULL);
								if (btree_search((ptd->cs).request_times, &rt)==1) {
									struct request_timestamp *request = (struct request_timestamp *)btree_find(
											               (ptd->cs).request_times,
												       &rt);
									unsigned int download_rate = (unsigned int)(((double)subpiece_length)/difftime(rt.timestamp, request->timestamp));
									pthread_mutex_lock((ptd->cs).download_rates_mutex);
									vector_push_back((ptd->cs).download_rates, &download_rate);
									pthread_mutex_unlock((ptd->cs).download_rates_mutex);
									btree_rem((ptd->cs).request_times, &rt);
								}
								unsigned int current_piece_length = (ptd->metadata_info_struct)->piece_length;
                                                                unsigned int max_piece_index = (*(ptd->total_download_size))/current_piece_length;
								if ( ((*(ptd->total_download_size)) % current_piece_length) == 0) {
                                                                        --max_piece_index;
                                                                }

                                                                unsigned int max_subpiece_index = current_piece_length / 16384;
                                                                if ((current_piece_length % 16384) == 0) {
                                                                        --max_subpiece_index;
                                                                }
                                                                unsigned int final_piece_length = 0;
                                                                if ((*(ptd->current_piece_index)) == max_piece_index) {
                                                                        final_piece_length = (*(ptd->total_download_size)) % current_piece_length;
                                                                        if (final_piece_length == 0) {
                                                                                final_piece_length = current_piece_length;
                                                                        }
                                                                        max_subpiece_index = final_piece_length / 16384;
                                                                        if ((final_piece_length % 16384)==0) {
                                                                                --max_subpiece_index;
                                                                        }
                                                                }
								if (btree_no_of_nodes(*(ptd->received_subpieces))> max_subpiece_index) {
									// we have downloaded the entire piece. check sha1 hash
									// and write data to files

									unsigned int piece_len = current_piece_length;
									if (max_piece_index == *(ptd->current_piece_index)) {
										piece_len = final_piece_length;
									}
									unsigned char *sha1_hash_of_piece = compute_sha1_hash(
											                    ptd->current_piece, piece_len);
									if (check_sha1_hash_match(&(((ptd->metadata_info_struct)->pieces)[received_piece_index*20]), 
										  	       sha1_hash_of_piece)==0) {
										// hash matches
										free(sha1_hash_of_piece);
										printf("Hash of downloaded piece matches.\n");
										int write_res = write_data_to_files(ptd->current_piece, 
												    piece_len,
												    ptd->metadata_info_struct,
												    received_piece_index);
												 
										if (write_res == 0) {
											// successful write to file(s) on disk
											pthread_mutex_lock(ptd->downloaded_pieces_mutex);
											btree_insert(ptd->downloaded_pieces, &received_piece_index);
											if (btree_no_of_nodes(ptd->downloaded_pieces)== (*(ptd->total_pieces))) {
												printf("Completed Download.\n");
												exit(0);
											}
											pthread_mutex_lock(ptd->peer_pieces_mutex);
											for (int i=0; 
											     i<btree_no_of_nodes(ptd->downloaded_pieces);
											     ++i) {
												unsigned int curr_downloaded_piece_index =
												*((unsigned int *)btree_get(ptd->downloaded_pieces, i));
												struct peers_piece p;
												p.piece_index = curr_downloaded_piece_index;
												p.count = 1;
												btree_rem(ptd->peer_pieces, &p);
											}	
											pthread_mutex_unlock(ptd->downloaded_pieces_mutex);
											struct peers_piece *p = (struct peers_piece *)btree_get(ptd->peer_pieces, 0);
											int min_count = p->count;
											int occurance_count = 0;
											for (int i=0; 
											     i<btree_no_of_nodes(ptd->peer_pieces); 
											     ++i) {
												struct peers_piece *pp = (struct peers_piece *)btree_get(ptd->peer_pieces,i );
												if ((pp->count) < min_count) {
													min_count = pp->count;
													occurance_count = 1;
												}
												else if ((pp->count) == (min_count)) {
													++occurance_count;
												}
											}
											int piece_index_selector = rand() % occurance_count;
											int n=-1;
											for (int i=0; i<btree_no_of_nodes(ptd->peer_pieces);
												      ++i) {
												struct peers_piece *pp = (struct peers_piece *)btree_get(ptd->peer_pieces,i );
												if ((pp->count)==min_count) {
													++n;
													if (n==piece_index_selector) {
														
														*(ptd->have_piece_index) = *(ptd->current_piece_index);
														printf("Have piece index set to :%d\n", *(ptd->current_piece_index));
														if (*(ptd->send_have_messages)==0) {
															*(ptd->send_have_messages) = 1;
														}
														*(ptd->current_piece_index) = pp->piece_index;
																		
														if (*(ptd->init_piece_downloaded)==0) {
															*(ptd->init_piece_downloaded) = 1;
															printf("Successfully downloaded first piece.\n");
														}
														pthread_mutex_lock(ptd->downloaded_pieces_mutex);
														printf("Successfully downloaded piece with index: %d. Downloaded %d/%d pieces\n", *(ptd->have_piece_index), btree_no_of_nodes(ptd->downloaded_pieces),(*(ptd->total_pieces)) ); 
														pthread_mutex_unlock(ptd->downloaded_pieces_mutex);
														break;
													}		
												}
											}
											pthread_mutex_unlock(ptd->peer_pieces_mutex);
											free_btree(*(ptd->received_subpieces));
											*(ptd->received_subpieces) = init_btree(sizeof(unsigned int), compare_subpiece_index, print_subpiece_index);	
											if ( ((ptd->cs).client_interested) &&
											     ((ptd->cs).peer_to_client_choke_status == 0) ) {
												send_subpiece_request(client_socket_fd, ptd);
											}
										}
										else {
											// writing data to disk failed.
											printf("Downloaded piece matches sha1 hash but error "
											       "occurred when writing to files on disk.\n");
											// retry download
											free_btree(*(ptd->received_subpieces));
                                                                                        *(ptd->received_subpieces) = init_btree(sizeof(unsigned int), compare_subpiece_index, print_subpiece_index);
											if ( ((ptd->cs).client_interested) &&
                                                                                             ((ptd->cs).peer_to_client_choke_status == 0) ) {
                                                                                                send_subpiece_request(client_socket_fd, ptd);
                                                                                        }
										}
									}
									else {
										printf("Downloaded piece does not match hash, redownloading it.\n");
										// downloaded current_piece does not match hash
										free(sha1_hash_of_piece);
										free_btree(*(ptd->received_subpieces));
                                                                                *(ptd->received_subpieces) = init_btree(sizeof(unsigned int), compare_subpiece_index, print_subpiece_index);
										if ( ((ptd->cs).client_interested) &&
								     		     ((ptd->cs).peer_to_client_choke_status == 0) ) {
											send_subpiece_request(client_socket_fd, ptd);
										}
									}	
								}
								else {
									// still more subpieces to request for the current piece_index
									if ( ((ptd->cs).client_interested) &&
					   				     ((ptd->cs).peer_to_client_choke_status == 0) ) {
										send_subpiece_request(client_socket_fd, ptd);
									}
								}
							}
							else {
								if ( ((ptd->cs).client_interested) &&
						     		     ((ptd->cs).peer_to_client_choke_status == 0) ) {
									send_subpiece_request(client_socket_fd, ptd);
								}
							}
							pthread_mutex_unlock(ptd->received_subpieces_mutex);
							
						}	
					}
				}
				else {
					pthread_mutex_lock(ptd->received_subpieces_mutex);
					if ( ((ptd->cs).client_interested) &&
					     ((ptd->cs).peer_to_client_choke_status == 0) ) {
						send_subpiece_request(client_socket_fd, ptd);
					}
					pthread_mutex_unlock(ptd->received_subpieces_mutex);	
				}
				pthread_mutex_unlock(ptd->piece_index_mutex);
			}
			else if (recv_buff[4] == 8) {
				// client received cancel message
				printf("Client received cancel message from peer %s.\n", inet_ntoa((ptd->peer).sin_addr));
				unsigned int *cancelled_piece_index_ptr = (unsigned int *)(&(recv_buff[5]));
				unsigned int cancelled_piece_index = ntohl(*cancelled_piece_index_ptr);
				unsigned int *cancelled_offset_ptr = (unsigned int *)(&(recv_buff[9]));
				unsigned int cancelled_offset = ntohl(*cancelled_offset_ptr);
				unsigned int *cancelled_length_ptr = (unsigned int *)(&(recv_buff[13]));
				unsigned int cancelled_length = ntohl(*cancelled_length_ptr);
				struct request r;
				r.piece_index = cancelled_piece_index;
				r.begin = cancelled_offset;
				r.length = cancelled_length;
				dlist_erase_all((ptd->cs).requests, &r);
			}
		}
		for (int i=0; i<recv_bytes - (4+payload_len); ++i) {
			recv_buff[i] = recv_buff[payload_len+4+i];
		}
		recv_bytes -= (4+payload_len);
	}
}

int main(int argc, char *argv[])
{ 
	if (argc != 2) {
		printf("Please provide a magnet link as the first and only arguement.\n");
		return 0;
	}
	if (magnet_link_version(argv[1]) != 1) {
		printf("Unsupported magnet link. Program terminating.\n");
		return 0;
	}	
	srand(time(NULL));
	unsigned char magic_constant[8] = {0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80};
	struct vector *tracker_list = get_trackers(argv[1]);

	int NoOfTrackers = vector_get_size(tracker_list);
	
	unsigned int min_peer_list_len = 15; // Minimum accepted length of returned peer list
	unsigned int max_list_len = 0;
	pthread_mutex_t max_list_len_mutex;
	pthread_mutex_init(&max_list_len_mutex, NULL);

	struct obtain_peer_list_data *pl_metadata = (struct obtain_peer_list_data *)malloc(
			                                          sizeof(struct obtain_peer_list_data)*NoOfTrackers);
	for (int i=0; i<NoOfTrackers; ++i) {
		(pl_metadata[i]).te = (struct tracker_endpoint *)vector_read(tracker_list, i);
		(pl_metadata[i]).list_len = 0;
		(pl_metadata[i]).magnet_link = argv[1];
		(pl_metadata[i]).max_list_len = &max_list_len;
		(pl_metadata[i]).max_list_len_mutex = &max_list_len_mutex;
		memset((pl_metadata[i]).peer_id,0,20);
	}
	pthread_t tracker_comms_thread[NoOfTrackers];
	for (int i=0; i<NoOfTrackers; ++i) {
		if (pthread_create(&(tracker_comms_thread[i]), NULL,
				   obtain_peer_list_from_tracker, &(pl_metadata[i]))!=0) {
			printf("Error occurred creating thread to get a peer list from a tracker.\n");
			return 0;
		}
	}

	while (1) {
		if (max_list_len > min_peer_list_len) {
			for (int i=0; i<NoOfTrackers; ++i) {
				pthread_cancel(tracker_comms_thread[i]);
			}
			break;
		}		
	}
	for (int i=0; i<NoOfTrackers; ++i) {
		pthread_join(tracker_comms_thread[i], NULL);
	}
	int peer_list_index = get_max_peer_list_index(pl_metadata, NoOfTrackers);
	unsigned char peer_list[(max_list_len*6)+20];
	memcpy(peer_list, (pl_metadata[peer_list_index]).peer_list, (max_list_len*6)+20);
	unsigned char peer_id[20];
	memcpy(peer_id, (pl_metadata[peer_list_index]).peer_id, 20);
	free(pl_metadata);
	printf("Peer list obtained (containing %d peers)\n", max_list_len);

	
	pthread_t *peer_comms_thread = (pthread_t *)malloc(sizeof(pthread_t)*max_list_len);
	struct obtain_metadata_info_per_thread_data *obtain_md_info_per_thread_data = 
		(struct obtain_metadata_info_per_thread_data *)malloc(sizeof(struct obtain_metadata_info_per_thread_data)*max_list_len);

	unsigned char *metadata_info_dict = 0;
	pthread_mutex_t metadata_info_dict_mutex;
	pthread_mutex_init(&metadata_info_dict_mutex, NULL);
	struct metadata_file_info_dict *metadata_info_struct = 0;
        pthread_mutex_t mi_mutex;
	pthread_mutex_init(&mi_mutex, NULL);
	unsigned char metadata_obtained = 0;

	for (int i=0; i<max_list_len; ++i) {
		(obtain_md_info_per_thread_data[i]).magnet_link = argv[1];
		(obtain_md_info_per_thread_data[i]).peer.sin_family = AF_INET;
		(obtain_md_info_per_thread_data[i]).client_socket_fd = -1;
		memcpy(&(((obtain_md_info_per_thread_data[i]).peer).sin_port), &(peer_list[20+(i*6)+4]), 2);
                memcpy(&(((obtain_md_info_per_thread_data[i]).peer).sin_addr), &(peer_list[20+(i*6)]), 4);
		memcpy((obtain_md_info_per_thread_data[i]).peer_id, peer_id, 20);
		(obtain_md_info_per_thread_data[i]).metadata_info_dictionary = &metadata_info_dict;
         	(obtain_md_info_per_thread_data[i]).metadata_info_dict_mutex = &metadata_info_dict_mutex;
		(obtain_md_info_per_thread_data[i]).mi_data = &metadata_info_struct;
        	(obtain_md_info_per_thread_data[i]).mi_data_mutex = &mi_mutex;
		(obtain_md_info_per_thread_data[i]).metadata_obtained = &metadata_obtained;
		pthread_create(&(peer_comms_thread[i]), NULL, obtain_metadata_info, &(obtain_md_info_per_thread_data[i]));
	}
		
	while (1) {
		if (metadata_obtained) {
			for (int i=0; i<max_list_len; ++i) {
				if ((obtain_md_info_per_thread_data[i]).client_socket_fd != -1) {
					close((obtain_md_info_per_thread_data[i]).client_socket_fd);
				}
				pthread_cancel(peer_comms_thread[i]);
			}
			break;
		}
	}	

	for (int i=0; i<max_list_len; ++i) {
		pthread_join(peer_comms_thread[i], NULL);
	}
	free(obtain_md_info_per_thread_data);
	// metadata info/torrent file obtained
	
	// create the relevant file(s) to download data into
	printf("Number of subpieces per piece: %lu\n", (metadata_info_struct->piece_length)/16384);
	if (create_files(metadata_info_struct)==1) {
		printf("Error creating files.\n");
		return 0;
	}	
	unsigned long int total_download_size = metadata_info_struct->length;
        if (total_download_size == 0) {
                struct doubly_linked_list *files = metadata_info_struct->files;
                struct link *curr_link = dlist_beg(files);
                struct link *end = dlist_end(files);
                while (curr_link != end) {
                        struct file *f = (struct file *)dlist_get_val(curr_link);
                        total_download_size += f->length;
                        curr_link = dlist_succ(curr_link);
                }               
        }
	if (((metadata_info_struct->pieces_length) % 20) != 0) {
		printf("Error in metadata pieces length, it isn't divisible by 20.\n");
		return 0;
	}
	unsigned int total_pieces = (metadata_info_struct->pieces_length)/20;
        unsigned int max_piece_index = total_download_size/(metadata_info_struct->piece_length); // 0 starting maximum piece index
        if ((total_download_size % (metadata_info_struct->piece_length)) == 0) {
                --max_piece_index;
        } 
	
 	int init_piece_downloaded = 0;
	pthread_mutex_t piece_index_mutex;
        pthread_mutex_init(&piece_index_mutex, NULL);
	int current_piece_index = -1;
	unsigned char *current_piece = (unsigned char *)malloc(metadata_info_struct->piece_length);
	
	struct binary_tree *peer_pieces = init_btree(sizeof(struct peers_piece), compare_peers_piece, print_peers_piece);
	pthread_mutex_t peer_pieces_mutex;
	pthread_mutex_init(&peer_pieces_mutex, NULL);

	struct binary_tree *downloaded_pieces = init_btree(sizeof(unsigned int), compare_index, print_index);
	pthread_mutex_t downloaded_pieces_mutex;
	pthread_mutex_init(&downloaded_pieces_mutex, NULL);

	struct binary_tree **received_subpieces = malloc(sizeof(struct binary_tree *));
	*received_subpieces = (struct binary_tree *)init_btree(sizeof(unsigned int), compare_subpiece_index, print_subpiece_index);
	pthread_mutex_t received_subpieces_mutex;
	pthread_mutex_init(&received_subpieces_mutex, NULL);

	int received_subpiece_count = 0;
	pthread_mutex_t received_subpiece_count_mutex;
	pthread_mutex_init(&received_subpiece_count_mutex, NULL);

	pthread_mutex_t download_rates_mutexes[max_list_len];
	for (int i=0; i<max_list_len; ++i) {
		pthread_mutex_init(&(download_rates_mutexes[i]), NULL);
	}

        int have_piece_index = -1;          // points to the current piece index that we are sending to peers through have messages
                                           // It is the last current_piece_index that was successfully downloaded
        int send_have_messages = 0;
	unsigned int manage_interested_peer_choking = 0;  // pointer to an integer that is 0 if the master thread does not need to manage 
                                                      // which peers are unchoked, otherwise is 1
        pthread_mutex_t manage_interested_peer_choking_mutex;
	pthread_mutex_init(&manage_interested_peer_choking_mutex, NULL);
	int optimistic_unchoke_peer_index = -1;

	struct data_transfer_per_thread_state *thread_data = 
	       (struct data_transfer_per_thread_state *)malloc(sizeof(struct data_transfer_per_thread_state)*max_list_len);
	for (int i=0; i<max_list_len; ++i) {
		thread_data[i].magnet_link = argv[1];
		thread_data[i].total_pieces = &total_pieces;
		thread_data[i].peer.sin_family = AF_INET;
                memcpy(&((thread_data[i].peer).sin_port), &(peer_list[20+(i*6)+4]), 2);
                memcpy(&((thread_data[i].peer).sin_addr), &(peer_list[20+(i*6)]), 4);
		memcpy(thread_data[i].peer_id, peer_id, 20);
		(thread_data[i]).cs.client_to_peer_choke_status = 1;
                (thread_data[i]).cs.peer_interested = 0;
                (thread_data[i]).cs.peer_to_client_choke_status = 1; 
                (thread_data[i]).cs.client_interested = 0;
                (thread_data[i]).cs.bitfield = 0;
                (thread_data[i]).cs.bitfield_length = 0;   
		(thread_data[i]).cs.requests = init_dlist((int)sizeof(struct request), compare_requests);
		(thread_data[i]).cs.request_times = init_btree(sizeof(struct request_timestamp), compare_rt, print_rt);
		(thread_data[i]).cs.download_rates = vector_null_init(sizeof(unsigned int));
		(thread_data[i]).cs.download_rates_mutex = &(download_rates_mutexes[i]);
		(thread_data[i]).cs.previous_download_rate = 0;
		thread_data[i].init_piece_downloaded = &init_piece_downloaded;
		thread_data[i].piece_index_mutex = &piece_index_mutex;
		thread_data[i].current_piece_index = &current_piece_index;
		thread_data[i].current_piece = current_piece;
		thread_data[i].metadata_info_struct = metadata_info_struct;
		thread_data[i].total_download_size = &total_download_size;
		thread_data[i].max_piece_index = max_piece_index;
		thread_data[i].peer_pieces = peer_pieces;
		thread_data[i].peer_pieces_mutex = &peer_pieces_mutex;
		thread_data[i].downloaded_pieces = downloaded_pieces;
		thread_data[i].downloaded_pieces_mutex = &downloaded_pieces_mutex;
		thread_data[i].received_subpieces = received_subpieces;
		thread_data[i].received_subpieces_mutex = &received_subpieces_mutex;
		thread_data[i].received_subpiece_count = &received_subpiece_count;
		thread_data[i].received_subpiece_count_mutex = &received_subpiece_count_mutex;
		thread_data[i].have_piece_indices_sent = init_btree(sizeof(unsigned int), compare_index, print_index);
		thread_data[i].have_piece_index = &have_piece_index;
		thread_data[i].send_have_messages = &send_have_messages;
		(thread_data[i]).switch_client_to_peer_choke_status = 0;
		pthread_mutex_init(&((thread_data[i]).switch_client_to_peer_choke_status_mutex), NULL); 
		(thread_data[i]).manage_interested_peer_choking = &manage_interested_peer_choking;
		(thread_data[i]).manage_interested_peer_choking_mutex = &manage_interested_peer_choking_mutex;
		thread_data[i].optimistic_unchoke_peer_index = &optimistic_unchoke_peer_index;
		thread_data[i].optimistic_unchoke_availability = 0;
		pthread_create(&(peer_comms_thread[i]), NULL, perform_data_exchange, &(thread_data[i]));
	}

	time_t time0 = time(NULL);
	unsigned char count = 0; // used to count the 10 second intervals, every third interval we change which peer is optimistically
				 // unchoked
	while (1) {
		time_t time1 = time(NULL);
		if (difftime(time1, time0)>10.0) {

			++count;
			
			// change whos choked based on each threads download rates from their peer
			unsigned int *download_rates = (unsigned int *)malloc(sizeof(unsigned int)*max_list_len);
			for (int i=0; i<max_list_len; ++i) {
				download_rates[i] = 0;
			}
			char interested_peers = 0;
			int min_interested_indices = -1;
			int min_indices = 0;
			for (int i=0; i<max_list_len; ++i) {
				unsigned int curr_download_rate = 0;
				pthread_mutex_lock((thread_data[i]).cs.download_rates_mutex);
				if (vector_get_size((thread_data[i]).cs.download_rates)>0) {
					for (int j=0; j<vector_get_size((thread_data[i]).cs.download_rates); ++j) {
						curr_download_rate += *((unsigned int *)vector_read((thread_data[i]).cs.download_rates, j));
					}
					curr_download_rate = (curr_download_rate/vector_get_size((thread_data[i]).cs.download_rates));
					curr_download_rate = (curr_download_rate + (thread_data[i]).cs.previous_download_rate)/2;
					download_rates[i] = curr_download_rate;
					(thread_data[i]).cs.previous_download_rate = curr_download_rate;
					vector_free((thread_data[i]).cs.download_rates);
					(thread_data[i]).cs.download_rates = vector_null_init(sizeof(unsigned int));
				}
				else {
					download_rates[i] = (thread_data[i]).cs.previous_download_rate / 2;
					(thread_data[i]).cs.previous_download_rate = download_rates[i];
				}
				pthread_mutex_unlock((thread_data[i]).cs.download_rates_mutex);
				if ((thread_data[i]).cs.peer_interested == 1) {
					if (!interested_peers) {
						interested_peers = 1;
						min_interested_indices = i;
					}
					if (download_rates[i] < download_rates[min_interested_indices]) {
						min_interested_indices = i;
					}
				}
				if (download_rates[i] < download_rates[min_indices]) {
					min_indices = i;
				}
			}
			//printf("Download rates from peers (Bytes per sec):\n");
			int no_of_unchoked_peers = 0;
			for (int i=0; i<max_list_len; ++i) {
				if ((thread_data[i]).cs.client_to_peer_choke_status == 0) {
					++no_of_unchoked_peers;
				}
				//printf("%u:%s\n ",download_rates[i],inet_ntoa(((thread_data[i]).peer).sin_addr) );
			}
			if (interested_peers) {
				printf("interested peers  ");
			}
			else {
				printf("no interested peers  ");
			}
			printf("%d unchoked peers\n", no_of_unchoked_peers);
			if (count < 3) {
				if (optimistic_unchoke_peer_index == -1) {
					if (!interested_peers) {
						// unchoke no peer - choke all peers
						/*for (int i=0; i<max_list_len; ++i) {
							if (thread_data[i].cs.client_to_peer_choke_status == 0) {
								pthread_mutex_lock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
								thread_data[i].switch_client_to_peer_choke_status = 1;
								pthread_mutex_unlock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
							}
						}*/
						
						/*
						// unchoke the 4 peers that have the highest download rate
						int peers_unchoke_list[4] = {min_indices};
						for (int i=0; i<max_list_len; ++i) {
							if ( (download_rates[i] >= download_rates[peers_unchoke_list[0]]) &&
							     (i != min_indices) ) {
								for (int j=0; j<3; ++j) {
									peers_unchoke_list[3-j] = peers_unchoke_list[2-j];
								}	
								peers_unchoke_list[0] = i;
							}
							else if ( (download_rates[i] >= download_rates[peers_unchoke_list[1]]) &&
								  (i!= min_indices) ) {
								for (int j=0; j<2; ++j) {
									peers_unchoke_list[3-j] = peers_unchoke_list[2-j];
								}
								peers_unchoke_list[1] = i;
							}
							else if ( (download_rates[i] >= download_rates[peers_unchoke_list[2]]) &&
                                                                  (i!= min_indices) ) {
                                                                for (int j=0; j<1; ++j) {
                                                                        peers_unchoke_list[3-j] = peers_unchoke_list[2-j];
                                                                }
                                                                peers_unchoke_list[2] = i;
                                                        }
							else if ( ( download_rates[i] >= download_rates[peers_unchoke_list[3]]) &&
                                                                  (i!= min_indices) ) {
								peers_unchoke_list[3] = i;
							}
						}
						for (int i=0; i<max_list_len; ++i) {
							unsigned char unchoke_peer = 0;
							for (int j=0; j<4; ++j) {
								if (peers_unchoke_list[j] == i) {
									unchoke_peer = 1;
								}
							}
							if ( ((unchoke_peer == 1) && (thread_data[i].cs.client_to_peer_choke_status == 1)) ||
							     ((unchoke_peer == 0) && (thread_data[i].cs.client_to_peer_choke_status == 0)) ) {
								pthread_mutex_lock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
                                                                thread_data[i].switch_client_to_peer_choke_status = 1;
                                                                pthread_mutex_unlock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
							}

						} */
						// unchoke all peers
						for (int i=0; i<max_list_len; ++i) {
							if (thread_data[i].cs.client_to_peer_choke_status == 1) {
								pthread_mutex_lock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
                                                                thread_data[i].switch_client_to_peer_choke_status = 1;
                                                                pthread_mutex_unlock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
							}
						}
					}
					else {
						int interested_peers_unchoke_list[4] = {min_interested_indices};
						for (int i=0; i<max_list_len; ++i) {
                                        		if ( (thread_data[i]).cs.peer_interested == 1) {
                                                		if ( (download_rates[i] >= download_rates[interested_peers_unchoke_list[0]]) 
								      && (i != min_interested_indices) )    {
                                                        		for (int j=0; j<3; ++j) {
                                                                		interested_peers_unchoke_list[3-j] = interested_peers_unchoke_list[2-j];
                                                        		}
                                                        		interested_peers_unchoke_list[0] = i;
                                                		}
                                                		else if ( ( download_rates[i] >= 
									     download_rates[interested_peers_unchoke_list[1]] ) && 
									  ( i != min_interested_indices ) )      {
                                                        		for (int j=0; j<2; ++j) {
                                                                		interested_peers_unchoke_list[3-j] = interested_peers_unchoke_list[2-j];
                                                        		}
                                                        		interested_peers_unchoke_list[1] = i;
                                                		}
                                                		else if (( download_rates[i] >= 
									   download_rates[interested_peers_unchoke_list[2]]) &&
                                                                           (i != min_interested_indices)) {
                                                        		for (int j=0; j<1; ++j) {
                                                                		interested_peers_unchoke_list[3] = interested_peers_unchoke_list[2];
                                                        		}
                                                        		interested_peers_unchoke_list[2] = i;
                                                		}
                                                		else if ((download_rates[i] >=
								          download_rates[interested_peers_unchoke_list[3]]) &&
                                                        	 		(i != min_interested_indices)) {
                                                        		interested_peers_unchoke_list[3] = i;
                                                		}
                                        		}
                                		}
						struct vector *unchoke_peer_indices_list = vector_null_init(sizeof(unsigned int));
					        for (unsigned int i=0; i<max_list_len; ++i) {
							if (download_rates[i] > (unsigned int)(interested_peers_unchoke_list[3])) {
								vector_push_back(unchoke_peer_indices_list, &i);
							}
						}
						for (unsigned int i=0; i<max_list_len; ++i) {
							unsigned char unchoke_peer = 0;
							for (int j=0; j<4; ++j) {
								if ((unsigned int)(interested_peers_unchoke_list[j]) == i) {
									unchoke_peer = 1;
									break;
								}
							}
							if (!unchoke_peer) {
								int pos = vector_search(unchoke_peer_indices_list, &i);
								if (pos >-1) {
									unchoke_peer = 1;
								}
							}
							if ( ((unchoke_peer) && (thread_data[i].cs.client_to_peer_choke_status == 1)) ||
							     ((!unchoke_peer) && (thread_data[i].cs.client_to_peer_choke_status == 0)) ) {
								pthread_mutex_lock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
								thread_data[i].switch_client_to_peer_choke_status = 1;
								pthread_mutex_unlock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));							      
							}
						}
						vector_free(unchoke_peer_indices_list);	
							
					}		
				}
				else {	
					if (!interested_peers) {
						/*
						int peers_unchoke_list[4] = {min_indices};
						for (int i=0; i<max_list_len; ++i) {
                                                        if ( (download_rates[i] >= download_rates[peers_unchoke_list[0]]) &&
                                                             (i != min_indices) ) {
                                                                for (int j=0; j<3; ++j) {
                                                                        peers_unchoke_list[3-j] = peers_unchoke_list[2-j];
                                                                }
                                                                peers_unchoke_list[0] = i;
                                                        }
                                                        else if ( (download_rates[i] >= download_rates[peers_unchoke_list[1]]) &&
                                                                  (i!= min_indices) ) {
                                                                for (int j=0; j<2; ++j) {
                                                                        peers_unchoke_list[3-j] = peers_unchoke_list[2-j];
                                                                }
                                                                peers_unchoke_list[1] = i;
                                                        }
                                                        else if ( (download_rates[i] >= download_rates[peers_unchoke_list[2]]) &&
                                                                  (i!= min_indices) ) {
                                                                for (int j=0; j<1; ++j) {
                                                                        peers_unchoke_list[3-j] = peers_unchoke_list[2-j];
                                                                }
                                                                peers_unchoke_list[2] = i;
                                                        }
                                                        else if ( ( download_rates[i] >= download_rates[peers_unchoke_list[3]]) &&
                                                                  (i!= min_indices) ) {
                                                                peers_unchoke_list[3] = i;
                                                        }
                                                }
						struct vector *unchoke_peer_list = vector_null_init(sizeof(unsigned int));
						unsigned int o_unchoke = (unsigned int)optimistic_unchoke_peer_index;
						vector_push_back(unchoke_peer_list, &o_unchoke);
						for (unsigned int i=0; i<max_list_len; ++i) {
							unsigned char continue_search = 1;
							for (int j=0; j<4; ++j) {
								if (vector_get_size(unchoke_peer_list)<4) {
									unsigned int curr_index = (unsigned int)(peers_unchoke_list[j]);
									if ( (curr_index==i) && (i!=o_unchoke) &&
									     ((j==0) || (peers_unchoke_list[j-1] != peers_unchoke_list[j])) )
									{
										vector_push_back(unchoke_peer_list, &curr_index);		
									}
									
								}
								else if (vector_get_size(unchoke_peer_list)==4) {
									continue_search = 0;
									break;
								}
							}
							if (!continue_search) {
								break;
							}
						}	
						for (unsigned int i=0; i<max_list_len; ++i) {
							if ( ((vector_search(unchoke_peer_list, &i)>=0) &&
							      ((thread_data[i]).cs.client_to_peer_choke_status == 1)) || 
							     ((vector_search(unchoke_peer_list, &i)==-1) &&
							      ((thread_data[i]).cs.client_to_peer_choke_status == 0)) ) {
								pthread_mutex_lock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
                                                                thread_data[i].switch_client_to_peer_choke_status = 1;
                                                                pthread_mutex_unlock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
							}
						}
						vector_free(unchoke_peer_list); */
						//unchoke all peers
						for (int i=0; i<max_list_len; ++i) {
                                                        if (thread_data[i].cs.client_to_peer_choke_status == 1) {
                                                                pthread_mutex_lock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
                                                                thread_data[i].switch_client_to_peer_choke_status = 1;
                                                                pthread_mutex_unlock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
                                                        }
                                                }
					}
					else {
						// optimistic_unchoke_peer_index defines a peer that is currently being 
						// optimistically unchoked
						if (thread_data[optimistic_unchoke_peer_index].cs.peer_interested == 1) {
							// uptimistaclly unchoked peer counts as one of the four interested and unchoked peers
							unsigned char excess_interested_peers = 0;
							for (int i =0; i<max_list_len; ++i) {
								if ( (thread_data[i].cs.peer_interested == 1) &&
								     (i != optimistic_unchoke_peer_index) ) {
									excess_interested_peers = 1;
									break;
								}
							}
							if (!excess_interested_peers) {
								struct vector *unchoke_peer_indices_list = vector_null_init(sizeof(unsigned int));
								for (unsigned int i=0; i<max_list_len; ++i) {
									if (download_rates[i] > download_rates[optimistic_unchoke_peer_index]) {
										vector_push_back(unchoke_peer_indices_list, &i);
									}
									if (i==(unsigned int)optimistic_unchoke_peer_index) {
										vector_push_back(unchoke_peer_indices_list, &i);					
									}
								}
								for (unsigned int i=0; i<max_list_len; ++i) {
									if ( ((vector_search(unchoke_peer_indices_list, &i)>-1) &&
									      (thread_data[i].cs.client_to_peer_choke_status == 1)) ||
									     ((vector_search(unchoke_peer_indices_list, &i)==-1) &&
                                                                              (thread_data[i].cs.client_to_peer_choke_status == 0)) ) {
										pthread_mutex_lock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
		                                                                thread_data[i].switch_client_to_peer_choke_status = 1;
                		                                                pthread_mutex_unlock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
									}
								}	
								vector_free(unchoke_peer_indices_list);
								
							}
							else {
								int interested_peers_unchoke_list[3] = {min_interested_indices};
								for (int i=0; i<max_list_len; ++i) {
									if ( (thread_data[i]).cs.peer_interested == 1) {
                                                                		if ( (download_rates[i] >= 
										        download_rates[interested_peers_unchoke_list[0]]) && 
										     (i != min_interested_indices) &&
										     (i != optimistic_unchoke_peer_index) )    {
                                                                        		for (int j=0; j<2; ++j) {
                                                                                		interested_peers_unchoke_list[2-j] = interested_peers_unchoke_list[1-j];
                                                                        		}
                                                                        		interested_peers_unchoke_list[0] = i;
                                                                		}
                                                                		else if ( (download_rates[i] >=
                                                                             		download_rates[interested_peers_unchoke_list[1]]) &&
                                                                                        (i != min_interested_indices) &&
										        (i != optimistic_unchoke_peer_index))  {
                                                                        		for (int j=0; j<1; ++j) {
                                                                                		interested_peers_unchoke_list[2-j] = 
													interested_peers_unchoke_list[1-j];
                                                                        		}
                                                                        		interested_peers_unchoke_list[1] = i;
                                                                		}
                                                                		else if ( (download_rates[i] >=
                                                                           		download_rates[interested_peers_unchoke_list[2]]) &&
                                                                           		(i != min_interested_indices) &&
											(i != optimistic_unchoke_peer_index)) {
                                                                        		interested_peers_unchoke_list[2] = i;
                                                                		}
									}
								}
								struct vector *unchoke_peer_indices_list = vector_null_init(sizeof(unsigned int));
								for (int i=0; i<3; ++i)	{
									if (i==0) {
										unsigned int curr_index = (unsigned int)(interested_peers_unchoke_list[i]);

										vector_push_back(unchoke_peer_indices_list, &curr_index);
									}
									else {
										if (interested_peers_unchoke_list[i] != interested_peers_unchoke_list[i-1]) {
											unsigned int curr_index = (unsigned int)(interested_peers_unchoke_list[i]); 	
											vector_push_back(unchoke_peer_indices_list, 
													&curr_index);
										}
									}
								}
								for (unsigned int i=0; i<max_list_len; ++i) {
									if ( (thread_data[i].cs.peer_interested == 0) &&
									     (download_rates[i] > 
									      download_rates[interested_peers_unchoke_list[3]]) ) {
										vector_push_back(unchoke_peer_indices_list, &i);
									}
								}
								unsigned int opt_unchk_peer = (unsigned int)optimistic_unchoke_peer_index;
								vector_push_back(unchoke_peer_indices_list, &opt_unchk_peer);
								for (unsigned int i=0; i<max_list_len; ++i) {
									if ( ((vector_search(unchoke_peer_indices_list, &i)>-1) &&
                                                                              (thread_data[i].cs.client_to_peer_choke_status == 1)) ||
                                                                             ((vector_search(unchoke_peer_indices_list, &i)==-1) &&
                                                                              (thread_data[i].cs.client_to_peer_choke_status == 0)) ) {
                                                                                pthread_mutex_lock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
                                                                                thread_data[i].switch_client_to_peer_choke_status = 1;
                                                                                pthread_mutex_unlock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
                                                                        }
								}
								vector_free(unchoke_peer_indices_list);
							}
						}
						else { 
							int interested_peers_unchoke_list[4] = {min_interested_indices};
							for (int i=0; i<max_list_len; ++i) {
								if ( (thread_data[i]).cs.peer_interested == 1) {
									if ( (download_rates[i] >=
										download_rates[interested_peers_unchoke_list[0]]) &&
					   					(i != min_interested_indices) )    {
			      							for (int j=0; j<3; ++j) {
		      									interested_peers_unchoke_list[3-j] = interested_peers_unchoke_list[2-j];
	      									}
      										interested_peers_unchoke_list[0] = i;
									}
									else if ( (download_rates[i] >=
  										    download_rates[interested_peers_unchoke_list[1]]) &&
										   (i != min_interested_indices) )  {
										for (int j=0; j<2; ++j) {
											interested_peers_unchoke_list[3-j] =
												interested_peers_unchoke_list[2-j];
										}
										interested_peers_unchoke_list[1] = i;
									}
                                                                        else if ( (download_rates[i] >=
                                                                                     download_rates[interested_peers_unchoke_list[2]]) &&
                                                                                   (i != min_interested_indices) ) {
										for (int j=0; j<1; ++j) {
                                                                                        interested_peers_unchoke_list[3-j] = 
												interested_peers_unchoke_list[2-j];
										}
										interested_peers_unchoke_list[2] = i;
                                                                        }
									else if ( (download_rates[i] >=
                                                                                     download_rates[interested_peers_unchoke_list[3]]) &&
                                                                                   (i != min_interested_indices) ) {
                                                                                interested_peers_unchoke_list[3] = i;
                                                                        }
                                                                }
							}
							struct vector *unchoke_peer_indices_list = vector_null_init(sizeof(unsigned int));
							unsigned int max_interested_peer_index = (unsigned int)(interested_peers_unchoke_list[0]);
							vector_push_back(unchoke_peer_indices_list, &max_interested_peer_index);
							for (int i=1; i<4; ++i) {
								if (interested_peers_unchoke_list[i] != interested_peers_unchoke_list[i-1]) {
									unsigned int curr_index = (unsigned int)(interested_peers_unchoke_list[i]);
									vector_push_back(unchoke_peer_indices_list, &curr_index);
								}
							}
							unsigned int opt_unchk_peer = (unsigned int)optimistic_unchoke_peer_index;
                                                        vector_push_back(unchoke_peer_indices_list, &opt_unchk_peer);

							for (int i=0; i<max_list_len; ++i) {
								unsigned char interested_peers_unchoke_presence = 0;
								for (int j=0; j<4; ++j) {
									if (i==interested_peers_unchoke_list[j]) {
										interested_peers_unchoke_presence = 1;
										break;
									}
								}
								if ( (!interested_peers_unchoke_presence) &&
								     (download_rates[i] > interested_peers_unchoke_list[3]) ) {
									unsigned int curr_index = i;
									vector_push_back(unchoke_peer_indices_list, &curr_index);
								}
							}
							for (unsigned int i=0; i<max_list_len; ++i) {
								if ( ((vector_search(unchoke_peer_indices_list, &i)>-1) &&
                                                                              (thread_data[i].cs.client_to_peer_choke_status == 1)) ||
                                                                             ((vector_search(unchoke_peer_indices_list, &i)==-1) &&
                                                                              (thread_data[i].cs.client_to_peer_choke_status == 0)) ) {
									pthread_mutex_lock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
									thread_data[i].switch_client_to_peer_choke_status = 1;
									pthread_mutex_unlock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
                                                                }
							}
							vector_free(unchoke_peer_indices_list);
						}
					}
				}
			}
			else { 
				// count == 3 , optimistically unchoke a new peer
				printf("previous optimistic_unchoke_peer_index:%d  ",optimistic_unchoke_peer_index);
				count = 0;
				if (!interested_peers) {
					unsigned int no_of_potential_peers_to_optimistically_unchoke = 0;
					for (int i=0; i<max_list_len; ++i) {
						if ( (thread_data[i].optimistic_unchoke_availability == 1) &&
					             (thread_data[i].cs.client_to_peer_choke_status == 1))	{
							++no_of_potential_peers_to_optimistically_unchoke;
						}
					}
					if (no_of_potential_peers_to_optimistically_unchoke>0) {
						int n = rand() % no_of_potential_peers_to_optimistically_unchoke;
						int temp = 0;
						for (int i=0; i<max_list_len; ++i) {
							if ( (thread_data[i].optimistic_unchoke_availability == 1) &&
                                                             (thread_data[i].cs.client_to_peer_choke_status == 1) ) {
								if (temp == n) {
									optimistic_unchoke_peer_index = i;
									break;
								}
								++temp;
							}
						}
					}
					else {
						unsigned char no_of_choked_peers = 0;
						for (int i=0; i<max_list_len; ++i) {
							if (thread_data[i].cs.client_to_peer_choke_status == 1) {
								++no_of_choked_peers;
							}
						}
						if (no_of_choked_peers == 0) {
							// all peers are unchoked
							optimistic_unchoke_peer_index = rand() % max_list_len;
						}
						else {
							int n = rand() % no_of_choked_peers;
							int temp = 0;
							for (int i=0; i<max_list_len; ++i) {
								if (thread_data[i].cs.client_to_peer_choke_status == 1) {
									if (temp == n) {
										optimistic_unchoke_peer_index = i;
										break;
									}
									++temp;
								}
							}printf("previous optimistic_unchoke_peer_index:%d  ",optimistic_unchoke_peer_index);
						}
					}
					// unchoke all peers
					for (int i=0; i<max_list_len; ++i) {
						if ( thread_data[i].cs.client_to_peer_choke_status == 1) {
							pthread_mutex_lock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
                                                        thread_data[i].switch_client_to_peer_choke_status = 1;
							pthread_mutex_unlock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
						}
					}
				}
				else {
					int interested_peers_unchoke_list[4] = {min_interested_indices};
					for (int i=0; i<max_list_len; ++i) {
						if ( (thread_data[i]).cs.peer_interested == 1) {
							if ( (download_rates[i] >=
								download_rates[interested_peers_unchoke_list[0]]) &&
								(i != min_interested_indices) )    {
								for (int j=0; j<3; ++j) {
	 								interested_peers_unchoke_list[3-j] = interested_peers_unchoke_list[2-j];
			 					}
					 			interested_peers_unchoke_list[0] = i;                                      
				      			}
							else if ( (download_rates[i] >=
									download_rates[interested_peers_unchoke_list[1]]) &&
									(i != min_interested_indices) )  {
								for (int j=0; j<2; ++j) {
									interested_peers_unchoke_list[3-j] =
										interested_peers_unchoke_list[2-j];
								}
								interested_peers_unchoke_list[1] = i;
							}
							else if ( (download_rates[i] >=
									download_rates[interested_peers_unchoke_list[2]]) &&
									(i != min_interested_indices) ) {
								for (int j=0; j<1; ++j) {
									interested_peers_unchoke_list[3-j] =
										interested_peers_unchoke_list[2-j];
								}
								interested_peers_unchoke_list[2] = i;
							}
							else if ( (download_rates[i] >=
									download_rates[interested_peers_unchoke_list[3]]) &&
									(i != min_interested_indices) ) {
								interested_peers_unchoke_list[3] = i;
							}
						}
					}
					struct vector *unchoke_peer_indices_list = vector_null_init(sizeof(unsigned int));
					unsigned int max_dr_interested_peer_index = (unsigned int)(interested_peers_unchoke_list[0]);
					vector_push_back(unchoke_peer_indices_list, &max_dr_interested_peer_index);
					for (int i=1; i<4; ++i) {
						if (interested_peers_unchoke_list[i] != interested_peers_unchoke_list[i-1]) {
							unsigned int curr_index = (unsigned int)(interested_peers_unchoke_list[i]);
							vector_push_back(unchoke_peer_indices_list, &curr_index);
						}
					}
					int no_of_optimistic_unchoke_possible_indices = 0;
					for (int i=0; i<max_list_len; ++i) {
						unsigned char interested_peers_unchoke_list_presence = 0;
						for (int j=0; j<4; ++j) {
							if (i==interested_peers_unchoke_list[j]) {
								interested_peers_unchoke_list_presence = 1;
							}
						}
						if ( (download_rates[i] > (download_rates[interested_peers_unchoke_list[3]])) &&
						     (!interested_peers_unchoke_list_presence) ) {
							unsigned int curr_index = i;
							vector_push_back(unchoke_peer_indices_list, &curr_index);
						}
						if ( (download_rates[i] <= (download_rates[interested_peers_unchoke_list[3]])) &&
						     (!interested_peers_unchoke_list) ) {
							++no_of_optimistic_unchoke_possible_indices;
						}
					}
					if (no_of_optimistic_unchoke_possible_indices > 0) {
						int n = rand() % no_of_optimistic_unchoke_possible_indices;
						int temp = 0;

						for (int i=0; i<max_list_len; ++i) {
							unsigned char interested_peers_unchoke_list_presence = 0;
                                                	for (int j=0; j<4; ++j) {
                                                        	if (i==interested_peers_unchoke_list[j]) {
                                                        	        interested_peers_unchoke_list_presence = 1;
									break;
                                                        	}
                                                	}
							if ( (download_rates[i] <= (download_rates[interested_peers_unchoke_list[3]])) &&
                                                     		(!interested_peers_unchoke_list) ) {
                                                        	if (temp == n) {
									optimistic_unchoke_peer_index = i;
									break;
								}
								++temp;
                                                	}
						}
					}
					else {
						int interested_peers_unchoke_list_len = 1;
						for (int i=1; i<4; ++i) {
							if (interested_peers_unchoke_list[i] != interested_peers_unchoke_list[i-1]) {
								++interested_peers_unchoke_list_len;
							}
						}
						int n = rand() % (max_list_len - interested_peers_unchoke_list_len);
						int temp = 0;
						for (int i=0; i<max_list_len; ++i) {
							unsigned char interested_peers_unchoke_list_presence = 0;
                                                        for (int j=0; j<4; ++j) {
                                                                if (i==interested_peers_unchoke_list[j]) {
                                                                        interested_peers_unchoke_list_presence = 1;
                                                                        break;
                                                                }
                                                        }
							if (!interested_peers_unchoke_list_presence) {
								if (temp == n) {
									optimistic_unchoke_peer_index = i;
									break;
								}
								++temp;
							}
						}
					}
					unsigned int optimistically_unchoke_index = (unsigned int)optimistic_unchoke_peer_index;
					vector_push_back(unchoke_peer_indices_list, &optimistically_unchoke_index);
					for (int i=0; i<max_list_len; ++i) {
						if ( ((thread_data[i].cs.client_to_peer_choke_status == 0) &&
                                                      (i != optimistic_unchoke_peer_index)) ||
                                                     ((thread_data[i].cs.client_to_peer_choke_status == 1) &&
                                                      (i == optimistic_unchoke_peer_index)) ) {
                                                        pthread_mutex_lock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
                                                        thread_data[i].switch_client_to_peer_choke_status = 1;
                                                        pthread_mutex_unlock(&(thread_data[i].switch_client_to_peer_choke_status_mutex));
                                                }	
					}
					vector_free(unchoke_peer_indices_list);
				}
				printf("current optimistic_unchoke_peer_index:%d\n",optimistic_unchoke_peer_index);
			}
			free(download_rates);
			time0 = time1;
		}
		pthread_mutex_lock(&manage_interested_peer_choking_mutex);
		if (manage_interested_peer_choking == 1) {
			// TODO: incorporate optimistic unchoked peer being either interested or not
			if ( (optimistic_unchoke_peer_index == -1) ||
			     (thread_data[optimistic_unchoke_peer_index].cs.peer_interested == 0) )  {
				unsigned int interested_unchoked_peer_count = 0;
				int index_with_minimum_previous_download_rate = -1;
				char first_index_encountered = 0;
				for (int i=0; i<max_list_len; ++i) {
					if ( ((thread_data[i]).cs.client_to_peer_choke_status == 0) &&
					     ((thread_data[i]).cs.peer_interested == 1) ) {
						++interested_unchoked_peer_count;	
						if (!first_index_encountered) {
							first_index_encountered = 1;
							index_with_minimum_previous_download_rate = i;
						}
						else {
							if ((thread_data[i]).cs.previous_download_rate < 
							    (thread_data[index_with_minimum_previous_download_rate]).cs.previous_download_rate) {
								index_with_minimum_previous_download_rate = i;
							}
						}
					}	
				}	
				if (interested_unchoked_peer_count > 4) {
					// we need to trim the amount of unchoked peers that are interested by choking the ones with
					// the worst previous_download_rate
					int unchoke_interested_peer_indices[4] = {index_with_minimum_previous_download_rate};
					for (int i=0; i<max_list_len; ++i) {
						if ( ((thread_data[i]).cs.client_to_peer_choke_status == 0) &&
						     ((thread_data[i]).cs.peer_interested == 1) ) {
							if ( ((thread_data[i]).cs.previous_download_rate >= 
							      (thread_data[unchoke_interested_peer_indices[0]]).cs.previous_download_rate) &&
							     (i != index_with_minimum_previous_download_rate) ) {
								for (int j=0; j<3; ++j) {
									unchoke_interested_peer_indices[3-j] = unchoke_interested_peer_indices[2-j];
								}
								unchoke_interested_peer_indices[0] = i;
							}
							else if ( ((thread_data[i]).cs.previous_download_rate >=
								   (thread_data[unchoke_interested_peer_indices[1]]).cs.previous_download_rate) &&
								  (i != index_with_minimum_previous_download_rate) ) {
								for (int j=0; j<2; ++j) {
									unchoke_interested_peer_indices[3-j] = unchoke_interested_peer_indices[2-j];
								}
								unchoke_interested_peer_indices[1] = i;
							}
							else if ( ((thread_data[i]).cs.previous_download_rate >=
								   (thread_data[unchoke_interested_peer_indices[2]]).cs.previous_download_rate) &&
								  (i != index_with_minimum_previous_download_rate) ) {
								for (int j=0; j<1; ++j) {
									unchoke_interested_peer_indices[3-j] = unchoke_interested_peer_indices[2-j];
								}
								unchoke_interested_peer_indices[2] = i;
							}		
							else if ( ((thread_data[i]).cs.previous_download_rate >=
								   (thread_data[unchoke_interested_peer_indices[3]]).cs.previous_download_rate) &&
								  (i != index_with_minimum_previous_download_rate) ) {
								unchoke_interested_peer_indices[3] = i;
							}
						}
					}
					for (int i=0; i<max_list_len; ++i) {
						if ( ((thread_data[i]).cs.client_to_peer_choke_status == 0) &&
						     ((thread_data[i]).cs.peer_interested == 1) ) {
							char curr_index_present = 0;
							for (int j=0; j<4; ++j) {
								if (unchoke_interested_peer_indices[j] == i) {
									curr_index_present = 1;
								}
								break;
							}
							if (!curr_index_present) {
								pthread_mutex_lock(&((thread_data[i]).switch_client_to_peer_choke_status_mutex));
								(thread_data[i]).switch_client_to_peer_choke_status = 1;
								pthread_mutex_unlock(&((thread_data[i]).switch_client_to_peer_choke_status_mutex));
							}
						}
					}

				}
				
			}
			else {
				if (thread_data[optimistic_unchoke_peer_index].cs.peer_interested == 1) {
					int no_of_unchoked_interested_peers = 0;
					int min_unchoke_interested_index = -1;
					for (int i=0; i<max_list_len; ++i) {
						if ( (i != optimistic_unchoke_peer_index) &&
					             (thread_data[i].cs.client_to_peer_choke_status == 0) &&
					             (thread_data[i].cs.peer_interested == 1) )	     {
							if (no_of_unchoked_interested_peers == 0) {
								min_unchoke_interested_index = i;
							}
							else {
								if (thread_data[i].cs.previous_download_rate < 
								    thread_data[min_unchoke_interested_index].cs.previous_download_rate) {
									min_unchoke_interested_index = i;
								}
							}
							++no_of_unchoked_interested_peers;
						}
					}
					if (no_of_unchoked_interested_peers > 3) {
						int unchoke_interested_peer_indices[3] = {min_unchoke_interested_index};
						for (int i=0; i<max_list_len; ++i) {
							if ( ((thread_data[i]).cs.client_to_peer_choke_status == 0) &&
							     ((thread_data[i]).cs.peer_interested == 1) &&
							     (i != optimistic_unchoke_peer_index) &&
							     (i != min_unchoke_interested_index) ) {
								if (thread_data[i].cs.previous_download_rate >=
								    thread_data[unchoke_interested_peer_indices[0]].cs.previous_download_rate)
								{
									for (int j=0; j<2; ++j) {
										unchoke_interested_peer_indices[2-j] = unchoke_interested_peer_indices[1-j];
									}
									unchoke_interested_peer_indices[0] = i;
								}		
								else if ( thread_data[i].cs.previous_download_rate >=
							   thread_data[unchoke_interested_peer_indices[1]].cs.previous_download_rate) {
									for (int j=0; j<1; ++j) {
										unchoke_interested_peer_indices[2-j] = unchoke_interested_peer_indices[1-j];
									}
									unchoke_interested_peer_indices[1] = i;
								}
								else if ( thread_data[i].cs.previous_download_rate >=
                                                           thread_data[unchoke_interested_peer_indices[2]].cs.previous_download_rate) {
                                                                        unchoke_interested_peer_indices[2] = i;
                                                                }
							}
						}
						for (int i=0; i<max_list_len; ++i) {
							unsigned char unchoke_interested_peer_index_present = 0;
							for (int j=0; j<3; ++j) {
								if (i== unchoke_interested_peer_indices[j]) {
									unchoke_interested_peer_index_present = 1;
									break;
								}
							}
							if (i == optimistic_unchoke_peer_index) {
								unchoke_interested_peer_index_present = 1;
							}
							if ( (!unchoke_interested_peer_index_present) &&
							     (thread_data[i].cs.client_to_peer_choke_status == 0) &&
							     (thread_data[i].cs.peer_interested == 1) ) {
								pthread_mutex_lock(&((thread_data[i]).switch_client_to_peer_choke_status_mutex));
                                                                (thread_data[i]).switch_client_to_peer_choke_status = 1;
                                                                pthread_mutex_unlock(&((thread_data[i]).switch_client_to_peer_choke_status_mutex));
							}
						}
					}
				}
			}
			manage_interested_peer_choking = 0;
		}
		pthread_mutex_unlock(&manage_interested_peer_choking_mutex);
	}	

	for (int i=0; i<max_list_len; ++i){
                pthread_join(peer_comms_thread[i], NULL);
        }
	
	return 0;	
}
