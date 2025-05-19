# Aplicatie client-server TCP si UDP pentru gestionarea mesajelor

### 1. Flow-ul general al server-ului
Pentru retinerea tuturor clientilor conectati vreodata la server, am folosit un
vector care accepta elemente de tipul:

```cpp
struct tcp_client {
    int tcp_sock_fd; // sockfd-ul clientului
    int status; // CONNECTED, DISCONNECTED, FIRST_CONNECTIONS
    char id[ID_LEN]; // ID-ul clientului
    vector<string> topics; // vectorul de topicuri al clientului
};
```

Se deschid doi socketi (unul TCP si unul UDP):
    - `int udp_sock_fd` - pentru receptionarea mesajelor UDP;
    - `int tcp_sock_fd` - socket-ul pe care se da *listen*.

Pentru retinerea tuturor socketi-lor am folosit un array de tipul *struct pollfd*
alocat dinamic si care e realocat in momentul in care nu mai e loc de noi socketi.

#### Evenimente
- conectarea unui client **TCP**:
    Se cauta clientul in vectorul de clienti dupa ID:
        - daca ID-ul clientului a fost gasit si clientul e *CONNECTED*, se afiseaza
        un mesaj corespunzator si se inchide conexiunea;
        - daca clientul a fost gasit si are status *DISCONNECTED*, se actualizeaza
        sockfd acestuia si *status = CONNECTED*;
        - daca clientul nu a fost gasit, este creat si adaugat in vector;
- receptionarea unui mesaj **UDP**:
    Se retine mesajul intr-o structura trimisa, ulterior, tuturor clientilor abonati
    la topicul respectiv; *--vezi sectiunea PROTOCOL*
- receptionarea unei comenzi de la **STDIN**:
    - `exit` -> se trimite mesajul catre fiecare client pentru a-si inchide conexiunea;
    ulterior se inchid socketii pentru TCP si UDP;
    - alte comenzi sunt considerate invalide;
- receptionarea unui mesaj **TCP**:
    Folosind functiile **strcmp, strstr** identific mesajul receptionat de la un client TCP:
    - `exit` : se modifica statusul clientului in DISCONNECTED;
    - `subscribe/unsubscribe` : se adauga/sterge topicul respectiv in/din vectorul de
    topicuri a clientului.

### 2. Flow-ul general al clientului
Se deschide un **socket TCP** pe care se face *listen*.

#### Evenimente
- receptionarea unei comenzi **STDIN**:
    - `exit` -> se trimite comanda catre server pentru ca clientul sa fie "deconectat";
    - `subscribe/unsubscribe` -> comanda e trimisa serverului care se ocupa de
    identificarea topicului la care este ulterior abonat clientul; se trimite si un **ack**
    sub forma de mesaj din partea serverului pentru confirmare actiunii;
- receptionarea unui mesaj de la server:
    - `exit` - > in momentul inchiderii, serverul trimite comanda tuturor clientulor sai;
    in momentul receptionarii, clientii isi inchid conexiunea;
    - receptionarea unui mesaj care incepe cu *Subscribed/Unsubscribed* = **ack**-ul
    serverului pentru confirmarea abonarii la un anumit topic;
    - receptionarea unui mesaj cu un continut mai mare de 50 bytes => mesaj **UDP**.

### 3. PROTOCOL
Pentru receptionarea de catre server a unui mesaj UDP, am folosit o structura:
```cpp
struct udp_message {
    char topic[TOPIC_SIZE];
    uint8_t type;
    char content[CONTENT_LEN];
};
```

Trimiterea mesajului implica incapsularea acestuia intr-o structura de forma:
```cpp
struct udp_to_tcp_message {
    struct msg_header hdr;
    char *content;
};
```
unde *struct msg_header* contine:
```cpp
struct msg_header {
    char udp_ip[16];
    uint16_t udp_port;
    char topic[TOPIC_SIZE];
    uint8_t type;
    int content_len;
};
```
Am completat campurile structurii `struct msg_header` cu *IP*-ul si *port*-ul clientului
*UDP*, topicul si tipul mesajului receptionat dar si lungimea continutului mesjului in
functie de tipul acestuia. In functie de *len*, am alocat memorie continutului mesajului
(acesta e receptionat ca avand o lungime de 1500 bytes insa nu toti octetii sunt
ocupati de un continut valid).
Structura de header este trimisa catre clientul TCP. Receptionarea acesteia se face
intr-o structura de tipul `struct udp_to_tcp_message` unde initial doar campul `hdr` este
ocupat. Avand lungimea continutului, se aloca memorie pentru acesta. Serverul trimite
separat continutul mesajului iar clientul, dupa receptionare, il adauga in structura principala.

Am recurs la implementarea acestui protocol intru-cat, la trimiterea structurii principale
in intregime, prin `char *` se trimite pointer-ul (adresa), nu continutul in sine. In momentul
receptionarii structurii, pointer-ul nu o sa mai pointeze la acelasi continut deoarece
programul clientului ruleaza intr-un spatiu de adrese separat de spatiul de adrese al serverului.

### 4. Programare defensiva
Am verificat validitatea argumentelor de executie a programului *server* si *subscriber*.
Am verificat ca serverul sa accepte doar comanda de `exit` de la **STDIN** si comenzi precum `subscribe` si `unsubscribe` de la clientii **TCP**.

Pentru clienti, am asigurat ca primesc comenzi de la **STDIN** de tipul `exit`, `subscribe`, `unsubscribe`, altele fiind considerate invalide.
