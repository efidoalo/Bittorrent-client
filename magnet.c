/*===============================
 *
 * File: magnet.c
 * Content: Implementation of magnet.h functions
 * and structs to process magnet links.
 * Date: 6/6/2025
 *
 *********************************/ 

#include "magnet.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>


void print_tracker(void *tr)
{
        struct tracker *tp = (struct tracker *)tr;
        printf("%s://%s:%u", tp->scheme, tp->url, tp->port);
}

struct peer_magnet
{
        char *host; // either hostname, ipv4 or ipv6 literal
        uint16_t port;
};

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
	if (strncmp(magnet_link, magnet_prefix, magnet_prefix_len) == 0) {
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
					size_t display_name_prefix_len = strlen(display_name_prefix);
					char *tracker_prefix = "&tr=";
					size_t tracker_prefix_len = strlen(tracker_prefix);
					char *x_pe_prefix = "&x.pe=";
					size_t x_pe_prefix_len = strlen(x_pe_prefix);
					char *announce_suffix = "announce";
					size_t announce_suffix_len = strlen(announce_suffix);
					while (index<magnet_link_len) {
						if (index <= (magnet_link_len - btmh_prefix_len)) {
							if (strncmp(&(magnet_link[index]), btmh_prefix, btmh_prefix_len)==0) {
								break; // btih link ended
							}
						}
						if (index <= (magnet_link_len - display_name_prefix_len)) {
							if (strncmp(&(magnet_link[index]), display_name_prefix, display_name_prefix_len)==0) {
								break;
							}
						}
						if (index <= (magnet_link_len - tracker_prefix_len)) {
							if ( strncmp(&(magnet_link[index]), tracker_prefix, tracker_prefix_len)==0) {
								break;
							}
						}
						if (index <= (magnet_link_len - x_pe_prefix_len) ) {
							if (strncmp(&(magnet_link[index]), x_pe_prefix, x_pe_prefix_len)==0) {
								break;
							}
						}
						if (index <= (magnet_link_len - announce_suffix_len)) {
							if (strncmp(&(magnet_link[index]), announce_suffix, announce_suffix_len)==0) {
								--index;
								break;
							}
						}
						++index;
					}
					info_hash_len = index - init_index;	
					if (info_hash_len == 40) {
						// info hash is hex encoded
						uint8_t *info_hash_raw_digest = (uint8_t *)malloc(20);
					        if (info_hash_raw_digest == NULL) {
							printf("Error on calling malloc to allocate memory for sha1 digest. %s.\n", strerror(errno));
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
								curr_byte += ((uint8_t)(high_4_bits - 48) << 4);
							}
							else {
								// invalid hex character (supposed to be 0-9, a-f, or A-F)
								printf("Invalid hexadecimal character found in sha1 digest of info dict which is supposed"
								       " to be hex encoded");
								free(info_hash_raw_digest);
								return NULL;
							}	
							if (low_4_bits >= 97) {
                                                                curr_byte += (uint8_t)(low_4_bits - 97 + 10);
                                                        }
                                                        else if (low_4_bits >= 65) {
                                                                curr_byte += (uint8_t)(low_4_bits - 65 + 10);
                                                        }
                                                        else if (low_4_bits >= 48) {
                                                                curr_byte += (uint8_t)(low_4_bits - 48);
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
					else if (info_hash_len == 32) {
						// base32 encoding of sha1 hash of info dict is used.
						uint8_t *info_hash_raw_digest = (uint8_t *)malloc(20);
						if (info_hash_raw_digest == NULL) {
							printf("Error allocating memory for sha1 hash of info dict. %s.\n", strerror(errno));
							return 0;
						}
						for (int i=0; i<20; ++i) {
							uint8_t curr_byte = 0;
							for (int j = ((i*8)/5); j<=((((i+1)*8)-1)/5); ++j) {
								if ( (magnet_link[init_index+j] >= 65) ) {
									// curr character is in range A-Z
									int left_shift = (3 + ((i*8) - (j*5)));
									if (left_shift >= 0) {
										curr_byte += ((magnet_link[init_index+j] - 65) << (3 + ((i*8) - (j*5))));
									}
									else {
										curr_byte += ((magnet_link[init_index+j] - 65) >> (3 + ((i*8) - (j*5))));
									}   	
								}
								else if ( (magnet_link[init_index+j] >= 50) ) {
									// curr character is in range 2-7
									int left_shift = (3 + ((i*8) - (j*5)));
                                                                        if (left_shift >= 0) {
                                                                                curr_byte += ((magnet_link[init_index+j] - 24) << (3 + ((i*8) - (j*5))));
                                                                        }
                                                                        else {
                                                                                curr_byte += ((magnet_link[init_index+j] - 24) >> (3 + ((i*8) - (j*5))));
                                                                        }
								}
								else {
									return 0; // unsupported base32 encoding used
								}
							}
							info_hash_raw_digest[i] = curr_byte;
						}
						return info_hash_raw_digest;
					}
				}		
			}
		}
		else if (type == 0) {
			// btmh specified
			printf("Requested magnet link format is currently unsupported.\n");
			return 0;
		}
		else {
			return 0; // ill formed type arguement
		}
	}
	else {
		printf("Ill formed magnet link.\n");
		return 0; // return 0 if the magnet link does not start with
			  // the magnet_prefix string
	}

}

uint8_t magnet_contains_tracker_list(char *magnet_link, uint8_t type)
{
	if (type == 1) {
		char *btih_prefix = "xt=urn:btih:";
		char *btmh_prefix = "xt=urn:btmh:";
		size_t btih_prefix_len = strlen(btih_prefix);
		size_t btmh_prefix_len = strlen(btmh_prefix);
		size_t magnet_link_len = strlen(magnet_link);
		for (int index=0; index<(magnet_link_len-btih_prefix_len); ++index) {
			if (strncmp(&(magnet_link[index]), btih_prefix, btih_prefix_len)==0) {
				index += btih_prefix_len;
				uint8_t tracker_present = 0;
				char *announce_suffix = "announce";
				size_t announce_suffix_len = strlen(announce_suffix);
				char *x_pe_string = "x.pe=";
				size_t x_pe_string_len = strlen(x_pe_string);
				char *tracker_prefix = "&tr=";
				size_t tracker_prefix_len = strlen(tracker_prefix);
				while (index < magnet_link_len) {
					if (index <= (magnet_link_len - x_pe_string_len)) {
						if (strncmp(&(magnet_link[index]), x_pe_string, x_pe_string_len)==0) {
							return 0;
						}
					}
					if (index <= (magnet_link_len - tracker_prefix_len)) {
						if (strncmp(&(magnet_link[index]), tracker_prefix, tracker_prefix_len) == 0) {
							return 1;
						}
					}
					if (index <= (magnet_link_len - announce_suffix_len) ) {
						if (strncmp(&(magnet_link[index]), announce_suffix, announce_suffix_len) == 0) {
							return 0;
						}
					}
					if (index <= (magnet_link_len - btmh_prefix_len) ) {
						if (strncmp(&(magnet_link[index]), btmh_prefix, btmh_prefix_len) == 0) { 
							return 0;
						}
					}
					++index;
				}
				return 0;
			}
		}
	}
	else if (type == 0) {
		char *btmh_prefix = "xt=urn:btmh:";
                size_t btmh_prefix_len = strlen(btmh_prefix);
		char *btih_prefix = "xt=urn:btih:";
		size_t btih_prefix_len = strlen(btih_prefix);
                size_t magnet_link_len = strlen(magnet_link);
                for (int index=0; index<(magnet_link_len-btmh_prefix_len); ++index) {   
                        if (strncmp(&(magnet_link[index]), btmh_prefix, btmh_prefix_len)==0) {
                                index += btmh_prefix_len;
				char *announce_suffix = "announce";
                                size_t announce_suffix_len = strlen(announce_suffix);
                                uint8_t tracker_present = 0;
                                char *x_pe_string = "x.pe=";
                                size_t x_pe_string_len = strlen(x_pe_string);
                                char *tracker_prefix = "&tr=";
                                size_t tracker_prefix_len = strlen(tracker_prefix);
                                while (index < magnet_link_len) {
                                        if (index <= (magnet_link_len - x_pe_string_len)) {
                                                if (strncmp(&(magnet_link[index]), x_pe_string, x_pe_string_len)==0) {
                                                        return 0;
                                                }
                                        }
                                        if (index <= (magnet_link_len - tracker_prefix_len)) {
                                                if (strncmp(&(magnet_link[index]), tracker_prefix, tracker_prefix_len) == 0) {
                                                        return 1;
                                                }
                                        }
					if (index <= (magnet_link_len - announce_suffix_len)) {
						if (strncmp(&(magnet_link[index]), announce_suffix, announce_suffix_len)==0) {
							return 0;
						}
					}
					if (index <= (magnet_link_len - btih_prefix_len)) {
						if (strncmp(&(magnet_link[index]), btih_prefix, btih_prefix_len)==0) {
							return 0; // btmh link ended
						}
					}
                                        ++index;
                                }
                                return 0;
                        }
                }
	}
}

struct vector *get_tracker_vector(char *magnet_link, uint8_t type)
{
	char *btih_prefix = "xt=urn:btih:";
	char *btmh_prefix = "xt=urn:btmh:";
	size_t magnet_link_len = strlen(magnet_link);
	size_t magnet_link_type_prefix_len = strlen(btih_prefix);
	char *tracker_prefix = "&tr=";
	size_t tracker_prefix_len = strlen(tracker_prefix);
	for (int index=0; index<=(magnet_link_len - magnet_link_type_prefix_len); ++index) {
		if ( (strncmp(&(magnet_link[index]), btih_prefix, magnet_link_type_prefix_len)==0) ||
		     (strncmp(&(magnet_link[index]), btmh_prefix, magnet_link_type_prefix_len)==0) )	{
			char *opposite_magnet_link_type_prefix = 0;
			if (type == 1) {
				opposite_magnet_link_type_prefix = btmh_prefix;
			}
			else {
				opposite_magnet_link_type_prefix = btih_prefix;
			}
			struct vector *tracker_vector = vector_null_init(sizeof(struct tracker), print_tracker);
			char *announce_suffix = "announce";
			size_t announce_suffix_len = strlen(announce_suffix);
			char *x_pe_prefix = "&x.pe=";
			size_t x_pe_prefix_len = strlen(x_pe_prefix);
			index += magnet_link_type_prefix_len;
			while (index < magnet_link_len) {
				if (index <= (magnet_link_len - magnet_link_type_prefix_len)) {
					if ( strncmp(&(magnet_link[index]), opposite_magnet_link_type_prefix, magnet_link_type_prefix_len) == 0) {
						return tracker_vector;
					}
				}
				if (index <= (magnet_link_len - x_pe_prefix_len)) {
					if (strncmp(&(magnet_link[index]), x_pe_prefix, x_pe_prefix_len)==0) {
						return tracker_vector;
					}
				}
				if (index <= (magnet_link_len - tracker_prefix_len)) {
					if (strncmp(&(magnet_link[index]), tracker_prefix, tracker_prefix_len)==0) {
						index += tracker_prefix_len;
						struct tracker curr_tracker;
						char *scheme_delimiter = "%3A%2F%2F";
						size_t scheme_delimiter_len = strlen(scheme_delimiter);
						char *port_delimiter = "%3A";
						size_t port_delimiter_len = strlen(port_delimiter);
						char *announce_delimiter = "%2F";
						size_t announce_delimiter_len = strlen(announce_delimiter);
						int init_index = index;
						int scheme_delimiter_index = index;
						while (scheme_delimiter_index < magnet_link_len) {
							if (scheme_delimiter_index <= (magnet_link_len - tracker_prefix_len)) {
								if (strncmp(&(magnet_link[scheme_delimiter_index]), tracker_prefix, tracker_prefix_len)==0) {
									scheme_delimiter_index = magnet_link_len;
									break;
								}
							}
							if (scheme_delimiter_index <= (magnet_link_len - x_pe_prefix_len)) {
								if (strncmp(&(magnet_link[scheme_delimiter_index]), x_pe_prefix, x_pe_prefix_len)==0) {
									scheme_delimiter_index = magnet_link_len;
									break;
								}
							}
							if (scheme_delimiter_index <= (magnet_link_len - announce_suffix_len)) {
								if (strncmp(&(magnet_link[scheme_delimiter_index]), announce_suffix, announce_suffix_len)==0) {
									scheme_delimiter_index = magnet_link_len;
									break;
								}
							}
							if (scheme_delimiter_index <= (magnet_link_len - magnet_link_type_prefix_len)) {
								if (strncmp(&(magnet_link[scheme_delimiter_index]), opposite_magnet_link_type_prefix,
															     magnet_link_type_prefix_len)==0) {
									scheme_delimiter_index = magnet_link_len;
									break;
								}
							}
							if (scheme_delimiter_index <= (magnet_link_len - scheme_delimiter_len)) {
								if (strncmp(&(magnet_link[scheme_delimiter_index]), scheme_delimiter, scheme_delimiter_len)==0) {
									break;
								}
							}
							else {
								scheme_delimiter_index = magnet_link_len;
								break;
							}
							++scheme_delimiter_index;
						}
						int port_delimiter_index = 0;
						if (scheme_delimiter_index < magnet_link_len) {
							port_delimiter_index = scheme_delimiter_index + scheme_delimiter_len;
						}
						while (port_delimiter_index < magnet_link_len) {
							if (port_delimiter_index <= (magnet_link_len - tracker_prefix_len)) {
								if (strncmp(&(magnet_link[port_delimiter_index]), tracker_prefix, tracker_prefix_len)==0) {
									port_delimiter_index = magnet_link_len;
									break;
								}
							}
							if (port_delimiter_index <= (magnet_link_len - x_pe_prefix_len)) {
								if (strncmp(&(magnet_link[port_delimiter_index]), x_pe_prefix, x_pe_prefix_len)==0) {
									port_delimiter_index = magnet_link_len;
									break;
								}
							}
							if (port_delimiter_index <= (magnet_link_len - announce_suffix_len)) {
								if (strncmp(&(magnet_link[port_delimiter_index]), announce_suffix, announce_suffix_len)==0) {
									port_delimiter_index = magnet_link_len;
									break;
								}
							}
							if (port_delimiter_index <= (magnet_link_len - magnet_link_type_prefix_len)) {
								if (strncmp(&(magnet_link[port_delimiter_index]), opposite_magnet_link_type_prefix,
														  magnet_link_type_prefix_len)==0) {
									port_delimiter_index = magnet_link_len;
									break;
								}
							}
							if (port_delimiter_index <= (magnet_link_len - port_delimiter_len)) {
								if (strncmp(&(magnet_link[port_delimiter_index]), port_delimiter, port_delimiter_len)==0) {
									break;		
								}
							}
							else {
								port_delimiter_index = magnet_link_len;
								break;
							}
							++port_delimiter_index;
						}
						int announce_delimiter_index = 0;
						if (port_delimiter_index < magnet_link_len) {
							announce_delimiter_index = port_delimiter_index + port_delimiter_len;		
						}
						while (announce_delimiter_index < magnet_link_len) {
							if (announce_delimiter_index <= (magnet_link_len - tracker_prefix_len)) {
								if (strncmp(&(magnet_link[announce_delimiter_index]), tracker_prefix, tracker_prefix_len)==0) {
									announce_delimiter_index = magnet_link_len;
									break;
								}
							}
							if (scheme_delimiter_index <= (magnet_link_len - x_pe_prefix_len)) {
								if (strncmp(&(magnet_link[announce_delimiter_index]), x_pe_prefix, x_pe_prefix_len)==0) {
									announce_delimiter_index = magnet_link_len;
									break;
								}
							}
							if (announce_delimiter_index <= (magnet_link_len - announce_suffix_len)) {
								if (strncmp(&(magnet_link[announce_delimiter_index]), announce_suffix, announce_suffix_len)==0) {
									announce_delimiter_index = magnet_link_len;
									break;
								}
							}
							if (announce_delimiter_index <= (magnet_link_len - magnet_link_type_prefix_len)) {
								if (strncmp(&(magnet_link[announce_delimiter_index]), opposite_magnet_link_type_prefix,
														  magnet_link_type_prefix_len)==0) {
									announce_delimiter_index = magnet_link_len;
									break;
								}
							}
							if (announce_delimiter_index <= (magnet_link_len - announce_delimiter_len)) {
								if (strncmp(&(magnet_link[announce_delimiter_index]), announce_delimiter, announce_delimiter_len)==0) {
									break;
								}
							}
							else {
								announce_delimiter_index = magnet_link_len;
								break;
							}
							++announce_delimiter_index;
						}
						// scheme_delimiter_index, port_delimiter_index, and announce_delimiter_index all either define the 0 starting index
						// in the tracker url of the first character of their delimiter strings or they equal magnet_link_len otherwise if
						// no correspomding delimiter string is found within the current tracker address. From this we can initialize the tracker
						// structure.
						if (scheme_delimiter_index == magnet_link_len) {
							curr_tracker.scheme = 0;
						}
						else {
							curr_tracker.scheme = (char *)malloc(scheme_delimiter_index-init_index+1);
							if (curr_tracker.scheme == NULL) {
								printf("Error allocating memory to store a tracker url scheme. %s.\n", strerror(errno));
								
								continue;									
							}
							memcpy(curr_tracker.scheme, &(magnet_link[init_index]), scheme_delimiter_index - init_index);
							(curr_tracker.scheme)[scheme_delimiter_index - init_index] = 0; // null terminate
						}
						if (port_delimiter_index == magnet_link_len) {
							if (announce_delimiter_index == magnet_link_len) {
								if (scheme_delimiter_index == magnet_link_len) {
									int url_index_end = init_index;
									while (url_index_end < magnet_link_len) {
										if (url_index_end <= (magnet_link_len - x_pe_prefix_len)) {
											if (strncmp(&(magnet_link[url_index_end]), x_pe_prefix, x_pe_prefix_len)==0) {
												break; 				
											}
										}
										if (url_index_end <= (magnet_link_len - magnet_link_type_prefix_len)) {
											if (strncmp(&(magnet_link[url_index_end]), opposite_magnet_link_type_prefix, 
												    magnet_link_type_prefix_len)==0)
											{
												break;
											}
										}
										if (url_index_end <= (magnet_link_len - tracker_prefix_len)) {
											if (strncmp(&(magnet_link[url_index_end]), tracker_prefix ,tracker_prefix_len)==0) {
												break;
											}
										}
										++url_index_end;
									}			
									curr_tracker.url = (char *)malloc(url_index_end - init_index + 1);
									if (curr_tracker.url == NULL) {
										printf("Error allocating memory for tracker url. %s.\n", strerror(errno));
										continue;		
									}
									memcpy(curr_tracker.url, &(magnet_link[init_index]), url_index_end - init_index);
									(curr_tracker.url)[url_index_end - init_index] = 0; 
								}
								else {
									init_index = scheme_delimiter_index + scheme_delimiter_len;
									int url_index_end = scheme_delimiter_index + scheme_delimiter_len;
									while (url_index_end < magnet_link_len) {
										if (url_index_end <= (magnet_link_len - x_pe_prefix_len)) {
											if (strncmp(&(magnet_link[url_index_end]), x_pe_prefix, x_pe_prefix_len)==0) {
												break;		
											}
										}
										if (url_index_end <= (magnet_link_len - magnet_link_type_prefix_len)) {
											if (strncmp(&(magnet_link[url_index_end]), opposite_magnet_link_type_prefix, 
																	    magnet_link_type_prefix_len)==0) {
												break;
											}
										}
										if ( url_index_end <= (magnet_link_len - tracker_prefix_len)) {
											if (strncmp(&(magnet_link[url_index_end]), tracker_prefix, tracker_prefix_len)==0) {
												break;
											}	
										}
										++url_index_end;
									}
									curr_tracker.url = (char *)malloc(url_index_end - init_index + 1);
									if ( curr_tracker.url == NULL ) {
										printf("Error allocating memory for tracker url. %s.\n", strerror(errno));
										continue;
									}
									memcpy(curr_tracker.url, &(magnet_link[init_index]), url_index_end - init_index);
									(curr_tracker.url)[url_index_end - init_index] = 0;	
								}	
							}
							else {	
								if (scheme_delimiter_index == magnet_link_len) {
									int url_index_end = announce_delimiter_index;
									curr_tracker.url = (char *)malloc(url_index_end - init_index + 1);
									if ( curr_tracker.url == NULL) {
										printf("Error allocating memory for tracker url. %s.\n", strerror(errno));
										continue;
									}
									memcpy(curr_tracker.url, &(magnet_link[init_index]), url_index_end - init_index);
									(curr_tracker.url)[url_index_end - init_index] = 0;
								}
								else {
									init_index = scheme_delimiter_index + scheme_delimiter_len;
									int url_index_end = announce_delimiter_index;
									curr_tracker.url = (char *)malloc(url_index_end - init_index + 1);
									if ( curr_tracker.url == NULL) {
										printf("Error allocating memory for tracker url. %s.\n", strerror(errno));
										continue;
									}
									memcpy(curr_tracker.url, &(magnet_link[init_index]), url_index_end - init_index);
									(curr_tracker.url)[url_index_end - init_index] = 0;
								}
							}	
						}
						else {
							if (scheme_delimiter_index == magnet_link_len) {
								int url_index_end = port_delimiter_index;
								curr_tracker.url = (char *)malloc(url_index_end - init_index);
								if (curr_tracker.url == NULL) {
									printf("Error allocating memory for tracker url. %s.\n", strerror(errno));
									continue;
								}	
								memcpy(curr_tracker.url, &(magnet_link[init_index]), url_index_end - init_index);
								(curr_tracker.url)[url_index_end - init_index] = 0;
							}
							else {
								init_index = scheme_delimiter_index + scheme_delimiter_len;
								int url_index_end = port_delimiter_index;
								curr_tracker.url = (char *)malloc(url_index_end - init_index);
								if (curr_tracker.url == NULL) {
									printf("Error allocating memory for tracker url. %s.\n", strerror(errno));
									continue;
								}
								memcpy(curr_tracker.url, &(magnet_link[init_index]), url_index_end - init_index);
								(curr_tracker.url)[url_index_end - init_index] = 0;
							}
						}
						if (port_delimiter_index == magnet_link_len) {
							curr_tracker.port = 0;
						}
						else {
							curr_tracker.port = strtol(&(magnet_link[port_delimiter_index+port_delimiter_len]), NULL, 10);	
						}
						vector_push_back(tracker_vector, &curr_tracker);
						continue;			
					}
				}
				++index;
			}
			return tracker_vector; 		
		}
	}
	return NULL;
}

uint8_t magnet_contains_peer_list(char *magnet_link, uint8_t type)
{
	return 0;
}

struct vector *get_peer_vector(char *magnet_link, uint8_t type)
{
	return NULL;
}
