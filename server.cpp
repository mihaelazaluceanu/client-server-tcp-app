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
#include <netinet/tcp.h>
#include "helpers.h"
#include "common.h"
using namespace std;

// vector de clienti TCP
vector<struct tcp_subscriber> subscribers;

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
  for (int i = 0; i < subscribers.size(); i++) {
    if (strcmp(subscribers[i].id, new_id) == 0) {
      if (subscribers[i].status == CONNECTED) {
        return CONNECTED;
      } else {
        subscribers[i].tcp_sock_fd = new_sock_fd;
        subscribers[i].status = CONNECTED;

        int flag = 1;
        setsockopt(new_sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
        
        return RECONNECTED;
      }
    }
  }

  // clientul este nou
  struct tcp_subscriber new_subscriber;
  new_subscriber.tcp_sock_fd = new_sock_fd;
  new_subscriber.status = CONNECTED;
  memcpy(new_subscriber.id, new_id, 10);
  subscribers.push_back(new_subscriber);

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
            close(new_client_fd);
            num_clients--;
          } else if (status == RECONNECTED) {
            cout << "New client " << new_id << " connected from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "." << endl;
            // caut in bufferul cu mesaje stocate clientul reconectat
            // trimit toate mesajele stocate pentru clientul respectiv
          } else if (status == FIRST_CONNECTION) {
            cout << "New client " << new_id << " connected from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "." << endl;
          }
        } else if (poll_fds[i].fd == udp_sock_fd) {
          struct sockaddr_in client_addr;
          socklen_t client_len = sizeof(struct sockaddr_in);

          // se primeste un mesaj de la un client UDP
          memset(buffer, 0, BUFF_LEN);
          rec = recvfrom(udp_sock_fd, buffer, sizeof(struct udp_message), 0, (struct sockaddr *)&client_addr, &client_len);
          DIE(rec < 0, "[SERV] Error while receiving message from UDP client.");

          struct udp_message *udp_msg = (struct udp_message *)buffer;

          // nu stiu ce tre sa se intample cand primesc asa mesaj

        } else if (poll_fds[i].fd == STDIN_FILENO) {
          cout << "Stdin command:";
          // se citeste comanda de la tastatura
          memset(buffer, 0, BUFF_LEN);
          rec = read(STDIN_FILENO, buffer, BUFF_LEN);
          DIE(rec <= 0, "[SERV] Error while reading from stdin.");
          buffer[rec - 1] = '\0';
          cout << buffer << endl;

          if (strcmp(buffer, "exit") == 0) {
            close(poll_fds[0].fd);
            close(tcp_sock_fd);
            close(udp_sock_fd);

            int buff_len = strlen(buffer);

            // trimitem mesaj clientilor sa se inchida
            for (int j = 3; j < num_clients; j++) {
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
            cout << "Client " << subscribers[i - 3].id << " disconnected." << endl;
            close(poll_fds[i].fd);
            poll_fds[i].fd = -1;
            num_clients--;
          } else {
            cout << "Received from client " << subscribers[i - 3].id << ": " << buffer << endl;
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
