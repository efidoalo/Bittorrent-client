# Bittorrent-client
A minimal program that can be used from the command line on Ubuntu to download files using the Bittorrent peer-to-peer protocol. The program places the download in ~/Downloads under the file/directory name suggested in the magnet link.
Compile with: gcc -I ~/Documents/Containers/C -c bittorrent.c
Link with: gcc ~/Documents/Containers/C/vector.o ~/Documents/Containers/C/doubly_linked_list.o ~/Documents/Containers/C/binary_tree.o bittorrent.o -o bittorrent -lm -lpthread
where the headers, source code and compiled object files for the data structures used (vector, doubly_linked_list and binary_tree) are all located in the directory
~/Documents/Containers/C.
The Bittorrent specification can be found here http://bittorrent.org/beps/bep_0003.html with relevant html links listed here http://bittorrent.org/beps/bep_0000.html.
As a result of bad practices in the code including the number of threads used and handling of pointers I am doing a rewrite of the program. Commits will ensue. As before the program will not implement
the whole Bittorrent specification but only a subset required to download files.
