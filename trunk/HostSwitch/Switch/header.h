#ifndef _HEADER_H
#define _HEADER_H

#define CLIENT_NAME_SIZE 8

#define MAX_MSG_SIZE 14

struct header_t
{
	char name[CLIENT_NAME_SIZE+1];
	int seq;
};

#endif