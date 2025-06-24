/*=====================================;
 *
 * File: bittorrent.c
 * Content: File for downloading and
 * uploading files via the peer to peer
 * network protocol Bittorrent.
 * Compile and link
 *
 * Execute via ./bittorrent "magnet_link" "minimum_number_of_peers_desired"  where minimum_number_of_peers_desired is a decimal number
 * minimum_number_of_peers_desired is an optional input arguement. If not specified a default of 10 is used
 *
 * link with: gcc -L~/Documents/Containers/C/ bittorrent.o -o bittorrent peer_interactions.o magnet.o peers.o ~/Documents/Containers/C/vector.o ~/Documents/Containers/C/binary_tree.o -lm
 *
 * Date: 6/6/2025
 *
 **************************************/

#include "magnet.h"
#include "peers.h"
#include "peer_interactions.h"
#include <stdlib.h>

int main(int argc, char *argv[])
{

	if (argc < 2) {
		printf("Invalid argument list passed to bittorrent executable. Must consist of exactly 1 argument giving the magnet link.\n");
		exit(EXIT_FAILURE);		
	}
	start_rand(); // seeds random number generator for successive rand() calls
	char *magnet_link = argv[1];
	char *minimum_number_of_peers = argv[2];
	int min_no_of_peers = 10;
	if (minimum_number_of_peers) {
		min_no_of_peers = strtol(minimum_number_of_peers, NULL, 10);
	}
	printf("Minimum number of peers selected is %d\n", min_no_of_peers);
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
		no_of_peer_discovery_threads = max_number_of_threads - 1;
	}

	pthread_t fetch_peer_list_thread[no_of_peer_discovery_threads];

	struct peer_discovery_thread_data *pdt = (struct peer_discovery_thread_data *)malloc(sizeof(struct peer_discovery_thread_data)*no_of_peer_discovery_threads);
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
	int NoOfPeers = -1;
	while (1) {
		if (pthread_mutex_lock(&access_peers_tree_mutex) != 0) {
			printf("Error acquiring mutex to check number of obtained peer addresses.\n");
		}
		NoOfPeers = btree_no_of_nodes((pdt[0]).peers_tree);
		if (pthread_mutex_unlock(&access_peers_tree_mutex) != 0) {
			printf("Error releasing mutex after checking number of peer list addresses.\n");
		}
		if (NoOfPeers >= min_no_of_peers) {
			for (int i=0; i<no_of_peer_discovery_threads; ++i) {
				if (pthread_cancel(fetch_peer_list_thread[i])!=0) {
					printf("Error joining peer discovery thread.\n");
					exit(EXIT_FAILURE);
				}
			}
			break;
		}
	}
	for (int i=0; i<no_of_peer_discovery_threads; ++i) {
		pthread_join(fetch_peer_list_thread[i], NULL);
	}
	printf("Peer list containing at least %d peers...\n", NoOfPeers);
	print_btree(pdt->peers_tree);
	
	struct binary_tree *peers_tree = pdt->peers_tree;
	int peer_interactions_thread_count = 0;
	if ((NoOfPeers/(max_number_of_threads-1))>0) {
		peer_interactions_thread_count = (max_number_of_threads-1);
	}
	else {
		peer_interactions_thread_count = 1;
	}
	pthread_t peer_interaction_threads[peer_interactions_thread_count];
	struct peer_interactions_thread_data *pit = get_peer_interactions_thread_data_structures( 
						      peer_interactions_thread_count,
						      NoOfPeers,
						      peers_tree,
						      max_number_of_threads);
	for (int i=0; i<peer_interactions_thread_count; ++i) {
		pthread_create(&(peer_interaction_threads[i]),
			       NULL,
			       peer_interactions,
			       &(pit[i]));
	}
	for (int i=0; i<peer_interactions_thread_count; ++i) {
                pthread_join(peer_interaction_threads[i], NULL);
        }


}
