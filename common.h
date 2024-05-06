#ifndef __COMMON_H__
#define __COMMON_H__

#include <vector>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
using namespace std;

#define MAX_CONNECTIONS 100
#define BUFF_LEN 1600
#define ID_LEN 10
#define TOPIC_SIZE 50
#define CONTENT_LEN 1500

// structura pentru mesajul de la clientul UDP la server
struct udp_message {
  char topic[TOPIC_SIZE];
  uint8_t type;
  char content[CONTENT_LEN];
};

struct msg_header {
  char udp_ip[16];
  uint16_t udp_port;
  char topic[TOPIC_SIZE];
  uint8_t type;
  int content_len;
};

// incapsuleaza un mesaj de la clientul UDP -> server -> clientul TCP
struct udp_to_tcp_message {
  struct msg_header hdr;
  char *content;
};

// status: conectat = 1, deconectat = -1, prima conectare = 0
#define CONNECTED 1
#define DISCONNECTED -1
#define FIRST_CONNECTION 0

// structura pentru retinerea informatiilor despre un client TCP
struct tcp_client {
  int tcp_sock_fd;
  int status; 
  char id[ID_LEN];
  vector<string> topics;
};

/*
 * Macro de verificare a erorilor
 * Exemplu:
 * 		int fd = open (file_name , O_RDONLY);
 * 		DIE( fd == -1, "open failed");
 */

#define DIE(assertion, call_description)                                       \
  do {                                                                         \
    if (assertion) {                                                           \
      fprintf(stderr, "(%s, %d): ", __FILE__, __LINE__);                       \
      perror(call_description);                                                \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#endif
