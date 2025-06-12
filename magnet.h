/*===========================;
 *
 * File: magnet.h
 * Content: header file for functions to
 * parse a megnet link.
 * Date: 6/6/2025
 *
 ***************************************/

#ifndef __MAGNET_H_INCLUDED__
#define __MAGNET_H_INCLUDED__

#include "vector.h"
#include <stdio.h>
#include <stdint.h>

// declarations to be defined in magnet.c
struct tracker;
void print_tracker(void *tr);
struct peer;

// returns 1 if magnet link includes a btih formatted link.
// otherwsie returns 0
uint8_t btih_present(char *magnet_link);

// Function that returns the 20 byte sha1 hash contained
// within the portion of the magnet link of type type as raw binary data.
// (type = 1 for btih, 0 for btmh). type portion of magnet link is assumed
// to have an info hash. Function returns null pointer if magnet_link is 
// illformedi or if type is not 1 or 0.
uint8_t *magnet_info_hash(char *magnet_link, uint8_t type);

// type is 0 for btmh, 1 for btih,
// the function checks for a tracker list in the magnet link portion
// of type given by the type parameter.
// returns 1 if there exists a tracker list, 0 otherwise
uint8_t magnet_contains_tracker_list(char *magnet_link, uint8_t type);

// returns a vector of trackers within the portion of the magnet link
// that has type type where type = 1 for btih, 0 for btmh. Assumes the given
// portion of the magnet link includes tracker data.
struct vector *get_tracker_vector(char *magnet_link, uint8_t type); 

// function that returns 1 if the magnet link portion with type type 
// (1 for btih, 0 for btmh) has any peers, 0 otherwise.
// CURRENTLY UNIMPLEMENTED - always returns 0
uint8_t magnet_contains_peer_list(char *magnet_link, uint8_t type);

// returns a vector of peers from the portion of the magnet link with type type
// (1 for btih, 0 for btmh). Assumes the given portion of the magnet link has
// peer data.
// CURRENTLY UNIMPLEMENTED - always returns NULL
struct vector *get_peer_vector(char *magnet_link, uint8_t type);
#endif

