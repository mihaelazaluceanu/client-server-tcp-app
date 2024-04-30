#include <iostream>
#include "common.h"
#include "helpers.h"
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
using namespace std;

int recv_all(int sockfd, void *buffer, size_t len) {
    size_t bytes_received = 0;
    size_t bytes_remaining = len;
    char *buff = (char *)buffer;

    while(bytes_remaining) {
        ssize_t rec = recv(sockfd, buff + bytes_received, bytes_remaining, 0);
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
        ssize_t rec = send(sockfd, buff + bytes_sent, bytes_remaining, 0);
        if (rec < 0) {
            cerr << "An error occured.";
            return -1;
        }
        
        bytes_sent += rec;
        bytes_remaining -= rec;
    }

    return bytes_sent;
}

void set_server_addr(struct sockaddr_in &serv_addr, uint16_t port, in_addr_t addr, socklen_t *socket_len) {
  // se completeaza in serv_addr adresa serverului, familia de adrese si portul
  // pentru conectare
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = addr;
  serv_addr.sin_port = htons(port);

  *socket_len = sizeof(struct sockaddr_in);
}

void start_client(int tcp_sock_fd) {
    int rec;
    char buffer[BUFF_LEN];

    struct pollfd poll_fds[MAX_CONNECTIONS];
    int num_clients = 2;

    // se adauga stdin ca un listener socket
    poll_fds[0].fd = STDIN_FILENO;
    poll_fds[0].events = POLLIN;
    // se adauga socketul TCP ca un listener socket
    poll_fds[1].fd = tcp_sock_fd;
    poll_fds[1].events = POLLIN;

    while (1) {
        rec = poll(poll_fds, num_clients, -1);
        DIE(rec < 0, "[CLIENT] Error while polling.");

        if (poll_fds[0].revents & POLLIN != 0) {
            // se citeste de la tastatura
            memset(buffer, 0, BUFF_LEN);
            rec = read(poll_fds[0].fd, buffer, BUFF_LEN);
            DIE(rec <= 0, "[CLIENT] Error while reading from stdin.");
            buffer[rec - 1] = '\0';

            if (strncmp(buffer, "exit", 4) == 0) {
                int buff_len = strlen(buffer);
                // se trimite dimensiunea buffer-ului catre server
                rec = send_all(tcp_sock_fd, &buff_len, sizeof(int));
                DIE(rec < 0, "[CLIENT] Unable to send message.");

                // se trimite mesajul catre server
                rec = send_all(tcp_sock_fd, (void *)buffer, buff_len);
                DIE(rec < 0, "[CLIENT] Unable to send message.");

                memset(buffer, 0, BUFF_LEN);
                // se inchide conexiunea
                close(tcp_sock_fd);
                close(STDIN_FILENO);
                exit(0);
            } else {
                int buff_len = strlen(buffer);
                // se trimite dimensiunea buffer-ului catre server
                rec = send_all(tcp_sock_fd, &buff_len, sizeof(int));
                DIE(rec < 0, "[CLIENT] Unable to send message.");

                // se trimite mesajul catre server
                rec = send_all(tcp_sock_fd, (void *)buffer, buff_len);
                DIE(rec < 0, "[CLIENT] Unable to send message.");
            }
        } else if (poll_fds[1].revents & POLLIN != 0) {
            // se primeste mesaj de la server
            memset(buffer, 0, BUFF_LEN);

            // se primeste un dimensiunea mesajului de la server
            int buff_len;
            rec = recv_all(poll_fds[1].fd, &buff_len, sizeof(int));
            DIE(rec < 0, "[CLIENT] Error while receiving message length from server.");

            // se primeste mesajul de la server
            rec = recv_all(tcp_sock_fd, (void *)buffer, buff_len);
            DIE(rec < 0, "[CLIENT] Unable to receive the message from the server.");

            if (strcmp(buffer, "exit") == 0) {
                // se inchide conexiunea
                close(tcp_sock_fd);
                exit(0);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, BUFSIZ);
    int rec;

    // se parseaza port-ul ca un numar
    uint16_t port;
    rec = sscanf(argv[3], "%hu", &port);
    DIE(rec != 1, "[CLIENT] Given port is invalid.");

    // se creaza un socket TCP pentru subscriber
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    DIE(sockfd < 0, "[CLIENT] Error while creating TCP socket.");

    // se completeaza in serv_addr adresa serverului, familia de adrese si portul
    // pentru conectare
    struct sockaddr_in serv_addr;
    socklen_t socket_len = sizeof(struct sockaddr_in);
    in_addr_t addr = inet_addr(argv[2]);
    set_server_addr(serv_addr, port, addr, &socket_len);

    // se conecteaza la server
    rec = connect(sockfd, (struct sockaddr *)&serv_addr, socket_len);
    DIE(rec < 0, "[CLIENT] Unable to connect to server.");

    char client_id[ID_LEN + 1];
    memset(client_id, 0, ID_LEN + 1);
    strcpy(client_id, argv[1]);

    rec = send_all(sockfd, (void *)client_id, ID_LEN + 1);
    DIE(rec < 0, "[CLIENT] Unable to send client id.");

    start_client(sockfd);

    close(sockfd);

    return 0;
}