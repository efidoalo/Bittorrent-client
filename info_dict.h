/*================================================;
 *
 * File: info_dict.h
 * Content: header files for obtaining info_dict 
 * from peer and constructing info_dict structure.
 * Date: 28/6/2025
 *
 ***********************************************/

#ifndef __INFO_DICT_H_INCLUDED__
#define __INFO_DICT_H_INCLUDED__

#include "peer_interactions.h"
#include "recv.h"
#include "vector.h"

// Attempts to request the info_dict from peer using BEP9
// Returns null pointer if attempt fails.
struct info_dict *get_info_dict(int client_socket_fd,
				int metadata_code,
				uint32_t metadata_size);

#endif
