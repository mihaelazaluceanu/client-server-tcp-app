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
        DIE(rec < 0, "[SERV] Error while receiving bytes from client.");

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
        DIE(rec < 0, "[SERV] Error while sending bytes to client.");
        
        bytes_sent += rec;
        bytes_remaining -= rec;
    }

    return bytes_sent;
}

void init_udp_client(int &udp_sock_fd, struct sockaddr_in &udp_subscriber_addr, uint16_t port, socklen_t *udp_sock_len) {
  // se obtine un socket UDP pentru receptionarea conexiunilor
  udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  DIE(udp_sock_fd < 0, "[SERV] Error while creating UDP socket.");

  // se dezactiveaza algoritmul lui Nagle
  int flag = 1;
  setsockopt(udp_sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

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

  // se dezactiveaza algoritmul lui Nagle
  int flag = 1;
  setsockopt(tcp_sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

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
        clients[i].status = CONNECTED;
        // se actualizeaza socketul clientului
        clients[i].tcp_sock_fd = new_sock_fd;

        // se dezactiveaza algoritmul lui Nagle
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
  
  // se dezactiveaza algoritmul lui Nagle
  int flag = 1;
  setsockopt(new_sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

  return FIRST_CONNECTION;
}

void start_server(int tcp_sock_fd, int udp_sock_fd) {
  int rec;
  char buffer[BUFF_LEN];

  rec = listen(tcp_sock_fd, MAX_CONNECTIONS);
  DIE(rec < 0, "[SERV] Error while listening for connections.");

  struct pollfd *poll_fds;
  int max_clients = 50;
  poll_fds = new struct pollfd[max_clients];

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

          // se realoca spatiu pentru vectorul de poll_fds daca este nevoie
          if (num_clients == max_clients) {
            // se dubleaza dimensiunea vectorului de poll_fds
            max_clients *= 2;
            poll_fds = (struct pollfd *)realloc(poll_fds, max_clients * sizeof(struct pollfd));
          }

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
          } else {
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

          // incapsulare mesaj de la clientul UDP -> server -> clientul TCP
          struct udp_to_tcp_message msg;
          memset(&msg, 0, sizeof(struct udp_to_tcp_message));

          // se seteaza adresa si portul clientului UDP
          memcpy(msg.hdr.udp_ip, inet_ntoa(client_addr.sin_addr), 16);
          msg.hdr.udp_port = ntohs(client_addr.sin_port);

          // se seteaza topic-ul si tipul mesajului
          memcpy(msg.hdr.topic, udp_msg->topic, TOPIC_SIZE);
          msg.hdr.type = udp_msg->type;

          // se seteaza dimensiunea continutului mesajului
          if (udp_msg->type == 0) {
            msg.hdr.content_len = sizeof(uint8_t) + sizeof(uint32_t);
          } else if (udp_msg->type == 1) {
            msg.hdr.content_len = sizeof(uint16_t);
          } else if (udp_msg->type == 2) {
            msg.hdr.content_len = sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint8_t);
          } else {
            msg.hdr.content_len = strlen(udp_msg->content);
          }

          // se aloca spatiu pentru continutul mesajului
          msg.content = new char[msg.hdr.content_len];
          memcpy(msg.content, udp_msg->content, msg.hdr.content_len);

          // se seteaza dimensiunea header-ului mesajului
          int hdr_len = sizeof(struct msg_header);

          // copie a topic-ului primit de la clientul UDP --fara wildcards
          char *cpy = strdup(msg.hdr.topic);
          // se itereaza prin fiecare client
          for (int x = 0; x < clients.size(); x++) {
            // daca clientul e deconectat, se trece la urmatorul
            if (clients[x].status == DISCONNECTED) {
              continue;
            }

            // se verifica daca clientul este abonat la topic-ul primit de la clientul UDP
            if (find(clients[x].topics.begin(), clients[x].topics.end(), msg.hdr.topic) != clients[x].topics.end()) {
                // se trimite dimensiunea header-ului catre client
                rec = send_all(clients[x].tcp_sock_fd, &hdr_len, sizeof(int));
                DIE(rec < 0, "[SERV] Unable to send message's length to client.");

                // se trimite headerul catre clientul TCP
                rec = send_all(clients[x].tcp_sock_fd, &msg.hdr, hdr_len);
                DIE(rec < 0, "[SERV] Error while sending message to client.");

                // se trimite continutul mesajului catre clientul TCP
                rec = send_all(clients[x].tcp_sock_fd, msg.content, msg.hdr.content_len);
                DIE(rec < 0, "[SERV] Error while sending message content to client.");
            } else {
              // vectorul de topicuri a clientului
              vector<string> topics = clients[x].topics;

              // se itereaza prin vectorul de topicuri a clientului
              for (int y = 0; y < topics.size(); y++) {
                char *topic = new char[topics[y].length() + 1];
                // se adauga un caracter NULL la finalul topic-ului
                strcpy(topic, topics[y].c_str());

                // daca nu exista wildcards in topic, se trece la urmatorul topic
                if (strchr(topic, '+') == NULL && strchr(topic, '*') == NULL) {
                  continue;
                }
                
                // resetare a copiei topic-ului
                strcpy(cpy, msg.hdr.topic);

                // topicul de la udp --fara wildcards
                char *seq1 = strtok_r(cpy, "/", &cpy);
                // topicul de la client -cu wildcards
                char *seq2 = strtok_r(topic, "/", &topic);
                while (seq2 != NULL && seq1 != NULL) {
                  if (strcmp(seq1, seq2) == 0) {
                    seq1 = strtok_r(NULL, "/", &cpy);
                    seq2 = strtok_r(NULL, "/", &topic);
                  } else if (strcmp(seq2, "+") == 0) {
                    seq1 = strtok_r(NULL, "/", &cpy);
                    seq2 = strtok_r(NULL, "/", &topic);
                  } else if (strcmp(seq2, "*") == 0) {
                    seq2 = strtok_r(NULL, "/", &topic);
                    if (seq2 == NULL) {
                      seq1 = NULL;
                      break;
                    }

                    while (seq1 != NULL && strcmp(seq1, seq2) != 0) {
                      seq1 = strtok_r(NULL, "/", &cpy);
                    }
                  } else {
                    break;
                  }
                }

                if (seq1 == NULL && seq2 == NULL) {
                  // se trimite dimensiunea mesajului catre client
                  rec = send_all(clients[x].tcp_sock_fd, &hdr_len, sizeof(int));
                  DIE(rec < 0, "[SERV] Unable to send message's length to client.");

                  // se trimite mesajul catre clientul TCP
                  rec = send_all(clients[x].tcp_sock_fd, &(msg.hdr), hdr_len);
                  DIE(rec < 0, "[SERV] Error while sending message to client.");

                  // se trimite continutul mesajului catre clientul TCP
                  rec = send_all(clients[x].tcp_sock_fd, msg.content, msg.hdr.content_len);
                  DIE(rec < 0, "[SERV] Error while sending message content to client.");

                  break;
                }
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
            }

            memset(buffer, 0, BUFF_LEN);
            exit(0);
          } else {
            cout << "Invalid command." << endl;
          }
        } else {
          // se primeste dimensiunea mesajului de la un client TCP
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
                poll_fds[i].fd = -1;
                break;
              }
            }
          } else if (strstr(buffer, "subscribe") == buffer) {
            char *cpy = strdup(buffer);

            // se separa topic-ul de la mesaj
            char *token = strtok_r(cpy, " ", &cpy);
            token = strtok_r(NULL, " ", &cpy);
            token[strlen(token)] = '\0';

            for (int j = 0; j < clients.size(); j++) {
              if (clients[j].tcp_sock_fd == poll_fds[i].fd) {
                // se adauga topic-ul in lista de topicuri a clientului
                clients[j].topics.push_back(token);

                // se creaza mesajul de confirmare
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
          } else if (strstr(buffer, "unsubscribe") == buffer) {
            char *cpy = strdup(buffer);

            // se separa topic-ul de la mesaj
            char *token = strtok_r(cpy, " ", &cpy);
            token = strtok_r(NULL, " ", &cpy);
            token[strlen(token)] = '\0';

            for (int j = 0; j < clients.size(); j++) {
              if (clients[j].tcp_sock_fd == poll_fds[i].fd) {
                clients[j].topics.erase(remove(clients[j].topics.begin(), clients[j].topics.end(), token), clients[j].topics.end());

                // se creaza mesajul de confirmare
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
          } else {
            cout << "Invalid command." << endl;
          }
        }
      }
    }
  }
}

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, BUFSIZ);
  // se verifica daca numarul de argumente este valid
  if (argc != 2) {
    DIE(true, "[SERV] Usage: ./server <PORT>");
  }

  int rec;
  // se parseaza port-ul ca un numar
  uint16_t port;
  rec = sscanf(argv[1], "%hu", &port);
  DIE(rec != 1, "[SERV] Error while reading the port.");

  // se verifica daca port-ul este valid
  if (port < 1024 || port > 65535) {
    DIE(true, "[SERV] Invalid port.");
  }

  // se completeaza in serv_addr adresa serverului, familia de adrese si portul
  struct sockaddr_in serv_addr;
  socklen_t socket_len;
  set_server_addr(serv_addr, port, &socket_len);

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

  // se inchid conexiunile
  close(udp_sock_fd);
  close(tcp_sock_fd);

  return 0;
}
