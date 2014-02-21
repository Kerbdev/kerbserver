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
    //krb5_kdc_req krb_as_req;
         //init_as_req(&krb_as_req,"Ivan");
         	//printf("%s",krb_as_req.client->data->data);
    //char en[250]="Hello USER";
    //char den[250];
    //char user_name[MAXDATASIZE];
    configuration conf;
    //get_config_param(&conf);
conf.
    //base64_encode((const BYTE *)en, (BYTE *)den, sizeof(en),1);
    //printf("Encode:%s\n",en);
    //base64_decode((const BYTE *)den ,(BYTE *)en, sizeof(den));
    //printf("Decode:%s",en);

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
        	krb5_kdc_req *as_rep=malloc(sizeof(krb5_kdc_req));
        	as_rep->padata=malloc(sizeof(krb5_pa_data));
        	as_rep->client->data=malloc(sizeof(krb5_data));
        	as_rep->addresses=malloc(sizeof(krb5_address));
        	as_rep->unenc_authdata=malloc(sizeof(krb5_authdata));
        	as_rep->second_ticket=malloc(sizeof(krb5_ticket));
        	memset(as_rep,0,sizeof(*as_rep));









        	//
        	char FLAGS=0;

        	recv_krb5_kdc_req(new_fd,as_rep,&FLAGS);
        	if(FLAGS){}
        close(new_fd);
        	exit(0);
        }
        close(new_fd);  // а этот сокет больше не нужен родителю
    }
    return 0;
}
