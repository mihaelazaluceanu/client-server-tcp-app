#ifndef __COMMON_H__
#define __COMMON_H__

#include <stddef.h>
#include <stdint.h>

int recv_all(int sockfd, void *buffer, size_t len);
int send_all(int sockfd, void *buffer, size_t len);

#define ID_LEN 10
#define TCP_MSG_LEN 64 // longest message is 63 characters + '\0' and '\n'
#define BUFF_LEN 1600
#define TOPIC_SIZE 50
#define CONTENT_LEN 1500

// structura pentru mesajul de la clientul UDP la server
struct udp_message {
  char topic[TOPIC_SIZE];
  uint8_t data_type;
  char content[CONTENT_LEN];
};

#define MAX_CONNECTIONS 100
// status: reconectat = 1, conectat = 0, prima conectare = -1
#define CONNECTED 0
#define RECONNECTED 1
#define FIRST_CONNECTION -1

struct tcp_subscriber {
  int tcp_sock_fd;
  int status; 
  char id[10];
  // struct tcp_topic *topic;
};

#endif
