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
	struct binary_tree *peers_btree;
	
};
