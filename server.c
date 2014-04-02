#include "Encode/base64.h"
#include "database/log.h"
#include "database/user_pass.h"
#include "query/request.h"
#include "message/message.h"
#include "dynamic/dynamic.h"
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
    get_config_param(&conf);
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
        	//malloc memory for krb5_kdc_req and recive
        	krb5_kdc_req *as_req=calloc(1,sizeof(krb5_kdc_req));
        	malloc_krb5_kdc_req(as_req);
        	recv_krb5_kdc_req(new_fd,as_req);
         	krb5_error *error=calloc(1,sizeof(krb5_error));
        	malloc_krb5_error(error);

        	//malloc memory for krb5_as_rep and send to client
        	krb5_kdc_rep *as_rep=calloc(1,sizeof(krb5_kdc_rep));
        	malloc_krb5_kdc_rep(as_rep);
        	//KRB_AS_REP(conf,as_rep,as_req, as_req->padata,error);//if error send KRB5_ERRO
    		//fprintf(stderr,"%s",as_rep->client->data->data);

        	send_krb5_kdc_rep(new_fd,*as_rep);

        	krb5_kdc_rep *new_as_rep=calloc(1,sizeof(krb5_kdc_rep));
        	malloc_krb5_kdc_rep(new_as_rep);
        	krb5_kdc_req *new_as_req=calloc(1,sizeof(krb5_kdc_req));
        	malloc_krb5_kdc_req(new_as_req);
        	krb5_ticket *ticket=calloc(1,sizeof(krb5_ticket));
        	malloc_krb5_ticket(ticket);

        	recv_krb5_kdc_req(new_fd,new_as_req);
        	KRB_TGS_REP_FORM(new_as_req, error, ticket);
        	send_krb5_kdc_rep(new_fd,*new_as_rep);
        	send_krb5_ticket(new_fd,*ticket);

        	krb5_ap_req *ap_req=calloc(1,sizeof(krb5_ap_req));
        	malloc_krb5_ap_req(ap_req);

        	krb5_ticket *new_ticket=calloc(1,sizeof(krb5_ticket));
        	malloc_krb5_ticket(new_ticket);
        	//recv_krb5_ticket(sockfd,new_ticket);
        	//NEED FUNCTION KRB_TGS_REP_CHECK


        	krb5_authenticator *authen=calloc(1,sizeof(krb5_authenticator));
        	malloc_krb5_authenticator(authen);
        	recv_krb5_ap_req(new_fd,ap_req);
        	recv_krb5_authenticator(new_fd,authen);
        	recv_krb5_ticket(new_fd,new_ticket);
        	krb_ap_req_check(ap_req, error);

        	krb5_ap_rep *ap_rep=calloc(1,sizeof(krb5_ap_rep));
        	malloc_krb5_ap_rep(ap_rep);

        	krb_ap_rep_form(ap_rep);
        	send_krb5_ap_rep(new_fd,*ap_rep);

        	//free memory
        	krb5_free_kdc_req(as_req);
        	krb5_free_kdc_rep(as_rep);
        	krb5_free_error(error);
        	krb5_free_kdc_req(new_as_req);
        	krb5_free_kdc_rep(new_as_rep);
        	krb5_free_ticket(ticket);
        	krb5_free_ap_req(ap_req);
        	krb5_free_ticket(new_ticket);
        	krb5_free_authenticator(authen);
        	krb5_free_ap_rep(ap_rep);
        close(new_fd);
        	exit(0);
        }
        close(new_fd);  // а этот сокет больше не нужен родителю
    }
    return 0;
}
