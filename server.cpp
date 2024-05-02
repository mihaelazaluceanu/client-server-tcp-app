#include <iostream>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <algorithm>
#include <netinet/tcp.h>
#include "helpers.h"
#include "common.h"
using namespace std;

// vector de clienti TCP
vector<struct tcp_client> clients;

int recv_all(int sockfd, void *buffer, size_t len) {
    size_t bytes_received = 0;
    size_t bytes_remaining = len;
    char *buff = (char *)buffer;

    while(bytes_remaining) {
        int rec = recv(sockfd, buff + bytes_received, bytes_remaining, 0);
        if (rec < 0) {
            cerr << "An error occured.";
            return -1;
        }

        bytes_received += rec;
        bytes_remaining -= rec;
    }

    return bytes_received;
}

int send_all(int sockfd, void *buffer, size_t len) {
    size_t bytes_sent = 0;
    size_t bytes_remaining = len;
    char *buff = (char *)buffer;

    while(bytes_remaining) {
        int rec = send(sockfd, buff + bytes_sent, bytes_remaining, 0);
        if (rec < 0) {
            cerr << "An error occured.";
            return -1;
        }
        
        bytes_sent += rec;
        bytes_remaining -= rec;
    }

    return bytes_sent;
}

void init_udp_client(int &udp_sock_fd, struct sockaddr_in &udp_subscriber_addr, uint16_t port, socklen_t *udp_sock_len) {
  // se obtine un socket UDP pentru receptionarea conexiunilor
  udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  DIE(udp_sock_fd < 0, "[SERV] Error while creating UDP socket.");

  memset(&udp_subscriber_addr, 0, sizeof(udp_subscriber_addr));
  udp_subscriber_addr.sin_family = AF_INET;
  udp_subscriber_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  udp_subscriber_addr.sin_port = htons(port);

  *udp_sock_len = sizeof(udp_subscriber_addr);
}

void init_tcp_client(int &tcp_sock_fd, struct sockaddr_in &tcp_subscriber_addr, uint16_t port, socklen_t *tcp_sock_len) {
  // se obtine un socket TCP pentru receptionarea conexiunilor
  tcp_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  DIE(tcp_sock_fd < 0, "[SERV] Error while creating TCP socket.");

  memset(&tcp_subscriber_addr, 0, sizeof(tcp_subscriber_addr));
  tcp_subscriber_addr.sin_family = AF_INET;
  tcp_subscriber_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  tcp_subscriber_addr.sin_port = htons(port);

  *tcp_sock_len = sizeof(tcp_subscriber_addr);
}

void set_server_addr(struct sockaddr_in &serv_addr, uint16_t port, socklen_t *socket_len) {
  // se completeaza in serv_addr adresa serverului, familia de adrese si portul
  // pentru conectare
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(port);

  *socket_len = sizeof(struct sockaddr_in);
}

int check_subscriber(char *new_id, int new_sock_fd) {
  for (int i = 0; i < clients.size(); i++) {
    if (strcmp(clients[i].id, new_id) == 0) {
      if (clients[i].status == CONNECTED) {
        // clientul este deja conectat si activ
        return CONNECTED;
      } else {
        // clientul a mai fost conectat si s-a reconectat
        clients[i].tcp_sock_fd = new_sock_fd;
        clients[i].status = CONNECTED;

        int flag = 1;
        setsockopt(new_sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
        
        return DISCONNECTED;
      }
    }
  }

  // clientul este nou
  struct tcp_client new_client;
  new_client.tcp_sock_fd = new_sock_fd;
  new_client.status = CONNECTED;
  memcpy(new_client.id, new_id, 10);
  clients.push_back(new_client);

  int flag = 1;
  setsockopt(new_sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

  return FIRST_CONNECTION;
}

void start_server(int tcp_sock_fd, int udp_sock_fd) {
  int rec;
  char buffer[BUFF_LEN];

  rec = listen(tcp_sock_fd, MAX_CONNECTIONS);
  DIE(rec < 0, "[SERV] Error while listening for connections.");

  struct pollfd poll_fds[MAX_CONNECTIONS];
  int num_clients = 3;

  // se adauga stdin ca un listener socket
  poll_fds[0].fd = STDIN_FILENO;
  poll_fds[0].events = POLLIN;
  // se adauga socketul UDP ca un listener socket
  poll_fds[1].fd = udp_sock_fd;
  poll_fds[1].events = POLLIN;
  // se adauga socketul TCP ca un listener socket
  poll_fds[2].fd = tcp_sock_fd;
  poll_fds[2].events = POLLIN;

  while (1) {
    // se asteapta evenimente pe cele 3 socketuri
    rec = poll(poll_fds, num_clients, -1);
    DIE(rec < 0, "[SERV] Error while polling.");

    // se verifica daca s-a primit un mesaj de la un client
    for (int i = 0; i < num_clients; i++) {
      if (poll_fds[i].revents & POLLIN != 0) {
        // conexiune de tip TCP
        if (poll_fds[i].fd == tcp_sock_fd) {
          struct sockaddr_in client_addr;
          socklen_t client_len = sizeof(struct sockaddr_in);

          // se accepta noua conexiune de tip TCP
          int new_client_fd = accept(tcp_sock_fd, (struct sockaddr *)&client_addr, &client_len);
          DIE(new_client_fd < 0, "[SERV] Error while accepting new TCP connection.");

          // se dezactiveaza algoritmul lui Nagle
          int flag = 1;
          rec = setsockopt(new_client_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

          // se adauga noul socket in lista de socketuri
          poll_fds[num_clients].fd = new_client_fd;
          poll_fds[num_clients].events = POLLIN;
          num_clients++;

          char new_id[ID_LEN + 1];
          memset(new_id, 0, ID_LEN + 1);
          // se obtine ID-ul clientului
          rec = recv_all(new_client_fd, (void *)new_id, ID_LEN + 1);
          DIE(rec < 0, "[SERV] Error while receiving the client's ID.");

          // se verifica statusul clientului
          int status = check_subscriber(new_id, new_client_fd);
          if (status == CONNECTED) {
            cout << "Client " << new_id << " already connected." << endl;
            
            // se trimite mesajul de exit catre client
            memset(buffer, 0, BUFF_LEN);
            memcpy(buffer, "exit", 4);
            buffer[4] = '\0';
            int buff_len = strlen(buffer);

            // se trimite dimensiunea buffer-ului catre client
            rec = send_all(new_client_fd, &buff_len, sizeof(int));
            DIE(rec < 0, "[SERV] Unable to send buffer's length to client.");

            // se trimite mesajul catre client
            rec = send_all(new_client_fd, (void *)buffer, buff_len);
            DIE(rec < 0, "[SERV] Error while sending the exit message to client.");

            close(new_client_fd);
            num_clients--;
          } else if (status == DISCONNECTED) {
            cout << "New client " << new_id << " connected from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "." << endl;
          } else if (status == FIRST_CONNECTION) {
            cout << "New client " << new_id << " connected from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "." << endl;
          }
        } else if (poll_fds[i].fd == udp_sock_fd) {
          struct sockaddr_in client_addr;
          socklen_t client_len = sizeof(struct sockaddr_in);

          // se primeste un mesaj de la un client UDP
          memset(buffer, 0, BUFF_LEN);
          rec = recvfrom(udp_sock_fd, (void *)buffer, sizeof(struct udp_message), 0, (struct sockaddr *)&client_addr, &client_len);
          DIE(rec < 0, "[SERV] Error while receiving message from UDP client.");

          struct udp_message *udp_msg = (struct udp_message *)buffer;
          // printf ("topic {%s} type {%u} content {%s}\n", udp_msg->topic, udp_msg->type, udp_msg->content);

          // incapsulare mesaj de la clientul UDP -> server -> clientul TCP
          struct udp_to_tcp_message msg;
          memset(&msg, 0, sizeof(struct udp_to_tcp_message));
          memcpy(msg.udp_ip, inet_ntoa(client_addr.sin_addr), 16);
          msg.udp_port = ntohs(client_addr.sin_port);
          memcpy(msg.topic, udp_msg->topic, TOPIC_SIZE);
          msg.type = udp_msg->type;
          memcpy(msg.content, udp_msg->content, CONTENT_LEN);

          // cout << msg.udp_ip << ":" << msg.udp_port << " - " << msg.topic << " - " << msg.type << " - " << msg.content << endl;

          int msg_len = sizeof(struct udp_to_tcp_message);
          // cout << "msg_len: " << msg_len << endl;

          // se trimite mesajul catre clientii TCP
          for (int j = 0; j < clients.size(); j++) {
            if (clients[j].status == CONNECTED) {
              if (find(clients[j].topics.begin(), clients[j].topics.end(), msg.topic) != clients[j].topics.end()) {
                // se trimite dimensiunea mesajului catre client
                rec = send_all(clients[j].tcp_sock_fd, &msg_len, sizeof(int));
                DIE(rec < 0, "[SERV] Unable to send message's length to client.");

                // se trimite mesajul catre clientul TCP
                rec = send_all(clients[j].tcp_sock_fd, (void *)&msg, msg_len);
                DIE(rec < 0, "[SERV] Error while sending message to client.");

                // cout << "Message with topic " << msg.topic << " was sent to client " << clients[j].id << "." << endl;
              }
            }
          }

        } else if (poll_fds[i].fd == STDIN_FILENO) {
          // se citeste comanda de la tastatura
          memset(buffer, 0, BUFF_LEN);
          rec = read(STDIN_FILENO, buffer, BUFF_LEN);
          DIE(rec <= 0, "[SERV] Error while reading from stdin.");
          buffer[rec - 1] = '\0';

          if (strcmp(buffer, "exit") == 0) {
            close(poll_fds[0].fd);
            close(tcp_sock_fd);
            close(udp_sock_fd);

            int buff_len = strlen(buffer);

            // trimitem mesaj clientilor sa se inchida
            for (int j = 3; j < num_clients; j++) {
              if (poll_fds[j].fd == -1) {
                continue;
              }

              // se trimite dimensiunea buffer-ului catre client
              rec = send_all(poll_fds[j].fd, &buff_len, sizeof(int));
              DIE(rec < 0, "[SERV] Unable to send buffer's length to client.");

              // se trimite mesajul catre client
              rec = send_all(poll_fds[j].fd, (void *)buffer, buff_len);
              DIE(rec < 0, "[SERV] Error while sending the exit message to client.");
              close(poll_fds[j].fd);
            }

            memset(buffer, 0, BUFF_LEN);
            exit(0);
          } else {
            cout << "Invalid command." << endl;
          }
        } else {
          // se primeste un dimensiunea mesajului de la un client TCP
          int buff_len;
          rec = recv_all(poll_fds[i].fd, &buff_len, sizeof(int));
          DIE(rec < 0, "[SERV] Error while receiving message length from client.");

          memset(buffer, 0, BUFF_LEN);
          // se primeste mesajul de la client
          rec = recv_all(poll_fds[i].fd, (void *)buffer, buff_len);
          DIE(rec < 0, "[SERV] Error while receiving message from client.");

          // se verifica daca mesajul este de tip "exit"
          if (strcmp(buffer, "exit") == 0) {
            for (int j = 0; j < clients.size(); j++) {
              if (clients[j].tcp_sock_fd == poll_fds[i].fd) {
                cout << "Client " << clients[j].id << " disconnected." << endl;
                clients[j].status = DISCONNECTED;
                close(poll_fds[i].fd);
                poll_fds[i].fd = -1;
                break;
              }
            }
          } else if (strstr(buffer, "subscribe ") == buffer) {
            char cpy[buff_len];
            strcpy(cpy, buffer);
            // se separa topic-ul de la mesaj
            char *token = strtok(cpy, " ");
            token = strtok(NULL, " ");
            token[strlen(token)] = '\0';

            for (int j = 0; j < clients.size(); j++) {
              if (clients[j].tcp_sock_fd == poll_fds[i].fd) {
                clients[j].topics.push_back(token);

                // se trimite mesajul de confirmare catre client
                memset(buffer, 0, BUFF_LEN);
                memcpy(buffer, "Subscribed to topic ", 20);
                buffer[strlen(buffer)] = '\0';
                strcat(buffer, token);

                int buff_len = strlen(buffer);
                // se trimite dimensiunea buffer-ului catre client
                rec = send_all(poll_fds[i].fd, &buff_len, sizeof(int));
                DIE(rec < 0, "[SERV] Unable to send buffer's length to client.");

                // se trimite mesajul catre client
                rec = send_all(poll_fds[i].fd, (void *)buffer, buff_len);
                DIE(rec < 0, "[SERV] Error while sending the exit message to client.");

                break;
              }
            }
          } else if (strstr(buffer, "unsubscribe ") == buffer) {
            char cpy[buff_len];
            strcpy(cpy, buffer);
            // se separa topic-ul de la mesaj
            char *token = strtok(cpy, " ");
            token = strtok(NULL, " ");
            token[strlen(token)] = '\0';

            for (int j = 0; j < clients.size(); j++) {
              if (clients[j].tcp_sock_fd == poll_fds[i].fd) {
                clients[j].topics.erase(remove(clients[j].topics.begin(), clients[j].topics.end(), token), clients[j].topics.end());

                // se trimite mesajul de confirmare catre client
                memset(buffer, 0, BUFF_LEN);
                memcpy(buffer, "Unsubscribed from topic ", 24);
                buffer[strlen(buffer)] = '\0';
                strcat(buffer, token);

                int buff_len = strlen(buffer);
                // se trimite dimensiunea buffer-ului catre client
                rec = send_all(poll_fds[i].fd, &buff_len, sizeof(int));
                DIE(rec < 0, "[SERV] Unable to send buffer's length to client.");

                // se trimite mesajul catre client
                rec = send_all(poll_fds[i].fd, (void *)buffer, buff_len);
                DIE(rec < 0, "[SERV] Error while sending the exit message to client.");

                break;
              }
            }
          }
        }
      }
    }
  }
}

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, BUFSIZ);
  
  int rec;
  // se parseaza port-ul ca un numar
  uint16_t port;
  rec = sscanf(argv[1], "%hu", &port);
  DIE(rec != 1, "[SERV] Given port is invalid.");

  // se completeaza in serv_addr adresa serverului, familia de adrese si portul
  struct sockaddr_in serv_addr;
  socklen_t socket_len;
  set_server_addr(serv_addr, port, &socket_len);
  // cout << serv_addr.sin_addr.s_addr << endl;

  // se obtine un socket UDP pentru receptionarea conexiunilor
  int udp_sock_fd;
  struct sockaddr_in udp_subscriber_addr;
  socklen_t udp_sock_len;
  init_udp_client(udp_sock_fd, udp_subscriber_addr, port, &udp_sock_len);

  // se asociaza adresa serverului cu socketul UDP creat folosind bind
  rec = bind(udp_sock_fd, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
  DIE(rec < 0, "[SERV] Binding UDP socket failed.");

  // se obtine un socket TCP pentru receptionarea conexiunilor
  int tcp_sock_fd;
  struct sockaddr_in tcp_subscriber_addr;
  socklen_t tcp_sock_len;
  init_tcp_client(tcp_sock_fd, tcp_subscriber_addr, port, &tcp_sock_len);

  // se asociaza adresa serverului cu socketul TCP creat folosind bind
  rec = bind(tcp_sock_fd, (const struct sockaddr *)&serv_addr, socket_len);
  DIE(rec < 0, "[SERV] Binding TCP socket failed.");

  // se pornește serverul
  start_server(tcp_sock_fd, udp_sock_fd);

  // se inchid cele doua socketuri
  close(udp_sock_fd);
  close(tcp_sock_fd);

  cout << "Server closed." << endl;
  return 0;
}
