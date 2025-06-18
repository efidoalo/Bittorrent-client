/*=====================================;
 *
 * File: bittorrent.c
 * Content: File for downloading and
 * uploading files via the peer to peer
 * network protocol Bittorrent.
 * Compile and link
 *
 * Execute via ./bittorrent "magnet_link"
 * Date: 6/6/2025
 *
 **************************************/

#include "magnet.h"
#include "peers.h"
#include <stdlib.h>

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Invalid argument list passed to bittorrent executable. Must consist of exactly 1 argument giving the magnet link.\n");
		exit(EXIT_FAILURE);		
	}
	start_rand(); // seeds random number generator for successive rand() calls
	char *magnet_link = argv[1];
	if (btih_present(magnet_link)==0) {
		printf("Unsupported magnet link format. Expected btih formate present.\n");
		exit(EXIT_FAILURE);
	}
	uint8_t *info_hash = magnet_info_hash(magnet_link, 1);
	uint8_t *peer_id = generate_peer_id(); // generates client peer id M0-1-0--
	if (info_hash == 0) {
		printf("Error obtaining info hash from magnet link.\n");
		exit(EXIT_FAILURE);
	}
	if (magnet_contains_tracker_list(magnet_link, 1)==0) {
		printf("Magnet link does not contain tracker list which "
		       "must be present as we do not implement the DHT protocol"
		       " for peer discovery.");
		exit(EXIT_FAILURE);
	}
	struct vector *tracker_vect = get_tracker_vector(magnet_link, 1);
	int NoOfTrackers = vector_get_size(tracker_vect);
	int max_number_of_threads = 5; // including this main thread
	int no_of_peer_discovery_threads = NoOfTrackers;
	if (NoOfTrackers >= (max_number_of_threads - 1)) {
		no_of_peer_discovery_threads = max_number_of_therads - 1;
	}

	pthread_t fetch_peer_list_thread[no_of_peer_discovery_threads];

	struct peer_discovery_thread_independent_data *pdt = (struct peer_discovery_thread_independent_data *)mallloc(sizeof(struct peer_discovery_thread_independent_data)*no_of_peer_discovery_threads);
	if (pdt==NULL) {
		printf("Error allocating memory for data used by peer discovery threads.%s.\n", strerror(errno));
	        exit(EXIT_FAILURE);	
	}
	pthread_mutex_t access_peers_tree_mutex;
	fill_peer_discovery_thread_structures(pdt, 
					      NoOfTrackers, 
					      no_of_peer_discovery_threads,
					      max_number_of_threads,
					      tracker_vect,
				      	      info_hash,
					      peer_id,
					      &access_peers_tree_mutex);
				              	      
	for (int i=0; i<no_of_peer_discovery_threads; ++i) {
		pthread_create(&(fetch_peer_list_thread[i]), NULL, peer_discovery, &(pdt[i]));
	}
}
