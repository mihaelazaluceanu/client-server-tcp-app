#include <iostream>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <vector>
#include "common.h"
#include <iomanip>
#include <cmath>
#include <netinet/tcp.h>
using namespace std;

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

void set_server_addr(struct sockaddr_in &serv_addr, uint16_t port, in_addr_t addr, socklen_t *socket_len) {
  // se completeaza in serv_addr adresa serverului, familia de adrese si portul
  // pentru conectare
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = addr;
  serv_addr.sin_port = htons(port);

  *socket_len = sizeof(struct sockaddr_in);
}

void start_client(int sockfd) {
    int rec;
    char buffer[BUFF_LEN];

    int num_clients = 2;
    struct pollfd poll_fds[num_clients];

    // se adauga stdin ca un listener socket
    poll_fds[0].fd = STDIN_FILENO;
    poll_fds[0].events = POLLIN;
    // se adauga socketul TCP ca un listener socket
    poll_fds[1].fd = sockfd;
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

            if (strcmp(buffer, "exit") == 0) {
                int buff_len = strlen(buffer);
                // se trimite dimensiunea buffer-ului catre server
                rec = send_all(sockfd, &buff_len, sizeof(int));
                DIE(rec < 0, "[CLIENT] Unable to send message.");

                // se trimite mesajul catre server
                rec = send_all(sockfd, (void *)buffer, buff_len);
                DIE(rec < 0, "[CLIENT] Unable to send message.");

                memset(buffer, 0, BUFF_LEN);
                // se inchide conexiunea
                close(sockfd);
                exit(0);
            } else if ((strstr(buffer, "subscribe") == buffer) || (strstr(buffer, "unsubscribe") == buffer)) {
                int buff_len = strlen(buffer);
                // se trimite dimensiunea buffer-ului catre server
                rec = send_all(sockfd, &buff_len, sizeof(int));
                DIE(rec < 0, "[CLIENT] Unable to send message.");

                // se trimite mesajul catre server
                rec = send_all(sockfd, (void *)buffer, buff_len);
                DIE(rec < 0, "[CLIENT] Unable to send message.");
            } else {
                cout << "Invalid command." << endl;
            }
        } else if (poll_fds[1].revents & POLLIN != 0) {
            // se primeste mesaj de la server
            memset(buffer, 0, BUFF_LEN);

            // se primeste un dimensiunea mesajului de la server
            int buff_len;
            rec = recv_all(poll_fds[1].fd, &buff_len, sizeof(int));
            DIE(rec < 0, "[CLIENT] Error while receiving message length from server.");

            // se primeste mesajul de la server
            rec = recv_all(sockfd, (void *)buffer, buff_len);
            DIE(rec < 0, "[CLIENT] Unable to receive the message from the server.");

            if (strcmp(buffer, "exit") == 0) {
                // se inchide conexiunea
                close(sockfd);
                exit(0);
            } else if ((strstr(buffer, "Subscribed") != NULL) || (strstr(buffer, "Unsubscribed") != NULL)) {
                // se confirma abonarea/dezabonarea clientului la un topic
                cout << buffer << endl;
            } else if (rec > 50) {
                // a fost receptionat un mesaj UDP
                struct udp_to_tcp_message udp_message;
                memcpy(&udp_message.hdr, buffer, sizeof(struct msg_header));

                // se verifica daca topic-ul este valid
                if (strlen(udp_message.hdr.topic) > 50) {
                    DIE(true, "[CLIENT] Invalid topic.");
                    continue;
                }

                udp_message.content = new char[udp_message.hdr.content_len];
                // se primeste continutul mesajului UDP
                rec = recv_all(sockfd, udp_message.content, udp_message.hdr.content_len);
                DIE(rec < 0, "[CLIENT] Unable to receive the message content from the server.");
                
                // se creaza introducerea comuna pentru afisare
                char comm[100];
                memset(comm, 0, 100);
                strcpy(comm, udp_message.hdr.udp_ip);
                strcat(comm, ":");
                strcat(comm, to_string(udp_message.hdr.udp_port).c_str());
                strcat(comm, " - ");
                strcat(comm, udp_message.hdr.topic);
                strcat(comm, " - ");

                if (udp_message.hdr.type == 0) {
                    uint8_t sign_byte = udp_message.content[0];
                    uint32_t nr = ntohl(*(uint32_t *)(udp_message.content + 1));
                    int print = nr;

                    if (sign_byte == 1) {
                        print = -print;
                    }

                    cout << comm << "INT - " << print << endl;
                } else if (udp_message.hdr.type == 1) {
                    uint16_t nr = ntohs(*(uint16_t *)(udp_message.content));
                    cout << comm << "SHORT_REAL - " << fixed << setprecision(2) << nr / 100.0 << endl;
                } else if (udp_message.hdr.type == 2) {
                    uint8_t sign_byte = udp_message.content[0];
                    uint32_t nr = ntohl(*(uint32_t *) (udp_message.content + 1));
                    uint8_t power = udp_message.content[5];
                    float div = pow(10, power);
                    float result = nr / div;
                    float print = result;

                    if (sign_byte == 1) {
                        print = -print;
                    }

                    cout << comm << "FLOAT - " << fixed << setprecision(power) << print << endl;
                } else if (udp_message.hdr.type == 3) {
                    cout << comm << "STRING - " << udp_message.content << endl;
                }
            }

            memset(buffer, 0, BUFF_LEN);
        }
    }
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, BUFSIZ);
    // se verifica numarul de argumente
    if (argc != 4) {
        DIE(true, "[CLIENT] Usage: ./subscriber <ID_CLIENT> <IP_SERVER> <PORT_SERVER>");
    }

    // se verifica daca ID-ul clientului este valid
    if (strlen(argv[1]) > ID_LEN) {
        DIE(true, "[CLIENT] Invalid client ID.");
    }

    // se verifica daca adresa IP a serverului este valida
    if (inet_addr(argv[2]) == INADDR_NONE) {
        DIE(true, "[CLIENT] Invalid server IP.");
    }

    int rec;
    // se parseaza port-ul ca un numar
    uint16_t port;
    rec = sscanf(argv[3], "%hu", &port);
    DIE(rec != 1, "[CLIENT] Error while parsing port.");

    // se verifica daca port-ul este valid
    if (port < 1024 || port > 65535) {
        DIE(true, "[CLIENT] Invalid port.");
    }

    // se creaza un socket TCP pentru subscriber
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    DIE(sockfd < 0, "[CLIENT] Error while creating TCP socket.");

    int flag = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

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

    // se trimite ID-ul clientului catre server
    rec = send_all(sockfd, (void *)client_id, ID_LEN + 1);
    DIE(rec < 0, "[CLIENT] Unable to send client's ID.");

    // se porneste clientul
    start_client(sockfd);

    // se inchide conexiunea
    close(sockfd);

    return 0;
}
