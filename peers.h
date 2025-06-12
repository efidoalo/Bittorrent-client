/*=============================;
 *
 * File: peers.h
 * Content: Header file declaring functions
 * and structs required for getting peer
 * list from trackers.
 * Date: 12/6/2025
 *
 *************************************/

#ifndef __PEERS_H_INCLUDED__
#define __PEERS_H_INCLUDED__

#include "binary_tree.h"

// struct for holding peer date
// ip port and possibly peer id
struct peer;

// struct that each thread uses when requesting peer
// lists from trackers. The thread uses this struct to
// append any peer lists that it has to the struct.
struct peer_discovery_thread_independent_data;



#endif
