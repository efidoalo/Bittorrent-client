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
#include <stdlib.h>

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Invalid argument list passed to bittorrent executable. Must consist of exactly 1 argument giving the magnet link.\n");
		exit(EXIT_FAILURE);		
	}
	char *magnet_link = argv[1];
	if (btih_present(magnet_link)==0) {
		printf("Unsupported magnet link format. Expected btih formate present.\n");
		exit(EXIT_FAILURE);
	}
	uint8_t *info_hash = magnet_info_hash(magnet_link, 1);
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
	int max_number_of_threads = 5;
		
}
