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

struct peer
{
	char *peer_id;
	uint8_t *ip_addr;
	uint8_t ip_version;
	uint16_t port;
};

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
			return res; // both peer1 and peer2 have identical ip
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
			return res;
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

struct peer_discovery_thread_independent_data
{
	struct vector *trackers_vector; // trackers that this thread will query
					// for peers
	struct vector *peers_vector;
	pthread_mutex_t *access_peers_vector_mutex;
};

void obtain_peer_list_from_tracker_host(struct addrinfo *tracker_addr,
                                        struct vetor *peers_vector,
                                        pthread_mutex_t *peers_access_mutex)
{
	if ( (tracer_addr->ai_family != AF_INET) && 
	     (tracker_addr->ai_family != AF_INET6) ) {
		return; // unsupported address family type
	}
	else {  // create client socket to match remote tracker socket with udp
		// service
		int client_socket_fd = socket(tracker_addr->ai_family,
				              tracker_addr->ai_socktype,
					      tracker_addr->ai_protocol);
		if (client_socket_fd == -1) {
			printf("Error obtaining client socket for communication to tracker. %s.\n", strerror(errno);
			return;
		}
		int tracker_socket_fd = socket(tracker_addr->ai_family,
					       tracker_addr->ai_socktype,
					       tracker_addr->ai_protocol);
		if (tracker_socket_fd == -1) {
			printf("Error obtaining socket for tracker for communication. %s.\n", strerror(errno));
			return;
		}
		if (bind(tracker_socket_fd, 
		         tracker_addr->ai_addr,
		         tracker_addr->ai_addrlen) < 0) {
			printf("Error binding tracker socket to tracker address.%s.\n", strerror(errno));
			return;
		}
					
	}
}

void obtain_peers_from_tracker(struct tracker *curr_tracker, 
			       struct vector *peers_vector,
		               pthread_mutex_t *peers_access_mutex)
{
	char *tracker_scheme_udp = "udp";
	size_t udp_scheme_len = strlen(tracker_scheme_udp);
	if (curr_tracker.scheme != 0) {
		if (strncmp(curr_tracker.scheme, 
			    tracker_scheme_udp, 
			    udp_scheme_len)==0) {
			// tracker should be acccessed over UDP
			if (curr_tracker.port == 0) {
				return; // port number required to access 
					// tracker program on its machine
			}
			struct addrinfo hints;
			hints.ai_flags = 0;
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = 17;
			hints.ai_addrlen = 0;
			hints.ai_addr = NULL;
			hints.ai_canonname = NULL;
			hints.ai_next = NULL;
			char service[10];
			memset(service, 0, 10);
			sprintf(service, "%u", curr_tracker.port);
			struct addrinfo *tracker_addr_list = NULL;
			if ( getaddrinfo(curr_tracker.url, service, &hints,
				         &tracker_addr_list) != 0) {
				printf("Error obtaining address for tracker %s.\n", curr_tracker.url);
				return;
			}
			while (tracker_addr_list) {
				obtain_peer_list_from_tracker_host(
						tracker_addr_list,
						peers_vector,
						peers_access_mutex);
				tracker_addr_list = tracker_addr_list->ai_next;
			}
		}
	}

}

void *peer_discovery(void *thread_data)
{
	struct peer_discovery_thread_independent_data *ptd = (struct peer_discovery_thread_independent_data *)thread_data;
	int NoOfTrackers = vector_get_size(ptd->trackers_vector);
	for (int i=0; i<NoOfTrackers; ++i) {
		struct tracker *curr_tracker = vector_read(ptd->trackers_vector,
				                           i);
		obtain_peers_from_tracker(curr_tracker, ptd->peers_vector, ptd->access_peers_vector_mutex);
	}
}
