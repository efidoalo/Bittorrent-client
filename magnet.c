/*===============================
 *
 * File: magnet.c
 * Content: Implementation of magnet.h functions
 * to process magnet links.
 * Date: 6/6/2025
 *
 *********************************/ 

#include "magnet.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

uint8_t btih_present(char *magnet_link)
{
	char *btih_magnet = "xt=urn:btih";
	size_t magnet_link_len = strlen(magnet_link);
	size_t btih_prefix_len = strlen(btih_magnet);
	int res = 0;
	for (int i=0; i<=(magnet_link_len - btih_prefix_len); ++i) {
		if (strncmp(&(magnet_link[i]), btih_magnet, btih_prefix_len) == 0) {
			res = 1;
			return res;
		}
	}
	return res;
}

uint8_t *magnet_info_hash(char *magnet_link, uint8_t type)
{
	char *magnet_prefix = "magnet:?";
	char *btih_prefix = "xt=urn:btih:";
	char *btmh_prefix = "xt=urn:btmh:";
	size_t magnet_prefix_len = strlen(magnet_prefix);
	size_t btih_prefix_len = strlen(btih_prefix);
	size_t btmh_prefix_len = strlen(btmh_prefix);
	if (strnmcp(magnet_link, magnet_prefix, magnet_prefix_len) == 0) {
		size_t magnet_link_len = strlen(magnet_link);
		if (type == 1) {
			// btih type specified
			int index = 0;
			for (index; index <= (magnet_link_len - btih_prefix_len); ++index) {
				if (strncmp(&(magnet_link[index]), btih_prefix, btih_prefix_len)==0) {
					int info_hash_len = 0;
					index += btih_prefix_len;
					int init_index = index;
					char *display_name_prefix = "&dn=";
					char *announce_suffix = "announce";
					size_t display_name_prefix_len = strlen(display_name_prefix);
					size_t announce_suffix_len = strlen(announce_suffix);
					for (index; index<magnet_link_len; ) {
						if (strncmp(&(magnet_link[index]), display_name_prefix, display_name_prefix_len)==0) {
							break;
						}
						else if (strncmp(&(magnet_link[index]), announce_suffix, announce_suffix_len)==0) {
							break;
						}
						++index;
					}
					info_hash_len = index - init_index;	
					if (info_hash_len == 40) {
						// info hash is hex encoded
						uint8_t *info_hash_raw_digest = (uint8_t *)malloc(20);
					        if (info_hash_raw_digest = NULL) {
							printf("Error on calling malloc to allocate memory for sha1 digest. %s.\n". strerror(errno));
							return 0;
						}
						for (int i=0; i<20; ++i) {
							uint8_t curr_byte = 0;
							char high_4_bits = magnet_link[init_index + (i*2)];
							char low_4_bits = magnet_link[init_index + (i*2) + 1];
							if (high_4_bits >= 97) {
								curr_byte += ((uint8_t)(high_4_bits - 97 + 10) << 4);
							}
							else if (high_4_bits >= 65) {
								curr_byte += ((uint8_t)(high_4_bits - 65 + 10) << 4);
							}
							else if (high_4_bits >= 48) {
								curr_byte += ((uint8_t)(high_4_bits - 48 + 10) << 4);
							}
							else {
								// invalid hex character (supposed to be 0-9, a-f, or A-F)
								printf("Invalid hexadecimal character found in sha1 digest of info dict which is supposed"
								       " to be hex encoded");
								free(info_hash_raw_digest);
								return NULL;
							}
							if (low_4_bits >= 97) {
                                                                curr_byte += (uint8_t)(high_4_bits - 97 + 10);
                                                        }
                                                        else if (low_4_bits >= 65) {
                                                                curr_byte += (uint8_t)(high_4_bits - 65 + 10);
                                                        }
                                                        else if (low_4_bits >= 48) {
                                                                curr_byte += (uint8_t)(high_4_bits - 48 + 10);
                                                        }
                                                        else {
                                                                // invalid hex character (supposed to be 0-9, a-f, or A-F)
                                                                printf("Invalid hexadecimal character found in sha1 digest of info dict which is supposed"
                                                                       " to be hex encoded");
                                                                free(info_hash_raw_digest);
                                                                return NULL;
                                                        }
							info_hash_raw_digest[i] = curr_byte;
						}
						return info_hash_raw_digest;	
					}
					else {
						// base32 encoding of sha1 hash of info dict is unsupported.
						printf("Unsupported encoding of 20 byte sha1 hash of info dict used.\n");
						return 0;
					}
				}		
			}
		}
		else if (type == 0) {
			// btmh specified
		}
		else {
			return 0; // ill formed type arguement
		}
	}
	else {
		return 0; // return 0 if the magnet link does not start with
			  // the magnet_prefix string
	}
}

uint8_t magnet_contains_tracker_list(char *magnet_link, uint8_t type)
{

}
