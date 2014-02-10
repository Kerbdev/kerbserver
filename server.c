#include "query/request.h"
#include "parser/get_config_param.h"
#include "Encode/base64.h"
#include "database/log.h"
#include "database/user_pass.h"
#define PORT "3490"  // порт, на который будут приходить соединения


void sigchld_handler(int s)
{
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

// получаем адрес сокета, ipv4 или ipv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(void)
{
    int sockfd, new_fd;  // слушаем на sock_fd, новые соединения - на new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // информация об адресе клиента
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    char en[250]="Hello USER";
    char den[250];
    char user_name[MAXDATASIZE];
    char ID_TGS[MAXDATASIZE];
    char date_time[MAXDATASIZE];
    configuration conf;
    get_config_param(&conf);

    base64_encode((const BYTE *)en, (BYTE *)den, sizeof(en),1);
    printf("Encode:%s\n",en);
    base64_decode((const BYTE *)den ,(BYTE *)en, sizeof(den));
    printf("Decode:%s",en);
while(1){
    sdddd();
}

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP
    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }


    // цикл через все результаты, чтобы забиндиться на первом возможном
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        return 2;
    }

    freeaddrinfo(servinfo); // всё, что можно, с этой структурой мы сделали

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // обрабатываем мёртвые процессы
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while(1) {  // главный цикл accept()
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s", s);

        if (!fork()) { // тут начинается дочерний процесс
        	close(sockfd);// дочернему процессу не нужен слушающий сокет
            char FLAGS=0;
        	char session_key_client_tgs_secret[MAXDATASIZE];
            char id_server_secret[MAXDATASIZE];
            int time_live_secret=0;
            char id_service[MAXDATASIZE];
            struct TGT tgt;
            struct AUTH_CLIENT AUTH;
            struct SERVICE_TICKET service_ticket;
            struct TICKET ticket;
            struct AUTH_CLIENT NEW_AUTH;

        	client_to_AS_REP(new_fd,date_time,user_name,ID_TGS,&FLAGS);
        	if(FLAGS){
        		strcpy(id_server_secret,ID_TGS);
        		strcpy(tgt.ip_client,s);
        		strcpy(tgt.user_name,user_name);
        	AS_REP(new_fd,session_key_client_tgs_secret,id_server_secret,time_live_secret,&tgt);
        	TGS_RECV(new_fd,id_service,tgt,AUTH);
        	TGS_REP(new_fd,ticket,service_ticket);
        	Connect_from_service(new_fd,NEW_AUTH,service_ticket);
        	confirm(new_fd,NEW_AUTH);}
        close(new_fd);
        	exit(0);
        }
        close(new_fd);  // а этот сокет больше не нужен родителю
    }
    return 0;
}
