#ifndef __COMMON_H__
#define __COMMON_H__

#include <stddef.h>
#include <stdint.h>
#include <vector>
using namespace std;

int recv_all(int sockfd, void *buffer, size_t len);
int send_all(int sockfd, void *buffer, size_t len);

#define ID_LEN 10
#define BUFF_LEN 1600
#define TOPIC_SIZE 50
#define CONTENT_LEN 1500

// structura pentru mesajul de la clientul UDP la server
struct udp_message {
  char topic[TOPIC_SIZE];
  uint8_t type;
  char content[CONTENT_LEN];
};

// incapsuleaza un mesaj de la clientul UDP -> server -> clientul TCP
struct tcp_message {
  char ip[16];
  uint16_t port;
  char topic[TOPIC_SIZE];
  uint8_t type;
  char content[CONTENT_LEN];
};

#define MAX_CONNECTIONS 100
// status: conectat = 1, deconectat = -1, prima conectare = 0
#define CONNECTED 1
#define DISCONNECTED -1
#define FIRST_CONNECTION 0

struct udp_to_tcp_message {
  char udp_ip[16];
  uint16_t udp_port;
  char topic[TOPIC_SIZE];
  uint8_t type;
  char content[CONTENT_LEN];
};

struct tcp_client {
  int tcp_sock_fd;
  int status; 
  char id[10];
  vector<string> topics;
};

#endif
