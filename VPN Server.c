#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>
#include "myheader.h"

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }


int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);       

   return tunfd;
}


void tunSelected(int tunfd, int sockfd, SSL *ssl){
    int  len;
    int BUFF_SIZE=2000;
    char buff[BUFF_SIZE];
struct sockaddr_in peerAddr;
    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
   //char sendBuf[200];
   //sprintf(buff, "GET / HTTP/1.1\nHos %s\n\n", hostname);
   SSL_write(ssl, buff, len);
   //write(sockfd, buff, len);
}


int socketSelected (int tunfd, int sockfd,SSL *ssl){
int BUFF_SIZE=2000;

    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from the tunnel---Socket Selected\n");

    bzero(buff, BUFF_SIZE);
    //len = read(sockfd, buff, BUFF_SIZE);
/* do {
     len = SSL_read (ssl, buff, sizeof(buff) - 1);
     buff[len] = '\0';
     printf("%s\n",buff);
    write(tunfd, buff, len);
   } while (len > 0); */
len = SSL_read (ssl, buff, sizeof(buff));
if(buff[0] == 'Q' && buff[1] == 'U' && buff[2] == 'I' && buff[3] == 'T')
{
  return -1;
}

printf("\n length of read is %d\t--%s\n",len,buff);
//struct ethheader *eth = (struct ethheader *)buff;
//printf("Hexadec packet type---%x\n",ntohs(eth->ether_type));

struct ipheader* ip=(struct ipheader*) (buff);//+sizeof(struct ethheader));

printf(" From : %s\n",inet_ntoa(ip->iph_sourceip));
printf(" To : %s\n",inet_ntoa(ip->iph_destip));

write(tunfd, buff, len);

    

}




int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (4451);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}



int login(char *user,char *password)
{
printf("login started\n");
    struct spwd *pw;
    char *epasswd;

    pw = getspnam(user);
    if (pw == NULL){
          printf("exit login1\n");
        return -1;
    }
    printf("After pw");

    epasswd = crypt(password,pw->sp_pwdp);
    if(strcmp(epasswd,pw->sp_pwdp)){
        printf("exit login2\n");
        return -1;
    }
printf("exit login3\n");
    return 1;
}


int processAuthentcation(SSL* ssl, int sock)
{
    char userbuf[1024],passbuf[1024];
    char username[40],password[40];
    int len = SSL_read (ssl, userbuf, sizeof(userbuf) - 1);
    userbuf[len] = '\0';
    
    strcpy(username,userbuf);
    printf("Received username: %s\n",username);
    //printf("sdsdsdsdsdsdhsjdhsjdhsjdh\n");

    len = SSL_read (ssl, passbuf, sizeof(passbuf) - 1);
    passbuf[len] = '\0';
    //printf("Received password: %s\n",buf1);

    strcpy(password,passbuf);
    printf("Received password: %s\n",password);

    int checksum=login(username,password);

    if(checksum==1)
       {
     printf("successful login from client");
     char *html ="success";
         SSL_write(ssl, html, strlen(html));
        return 1;
      }
    else{
           printf("failure to login from client");
           char *html ="failure";
           SSL_write(ssl, html, strlen(html));
           return 0;
    }

printf("After if check");

    // Construct and send the HTML page
/*
    char *html =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n\r\n"
    "<!DOCTYPE html><html>"
    "<head><title>Hello World</title></head>"
    "<style>body {background-color: black}"
    "h1 {font-size:3cm; text-align: center; color: white;"
    "text-shadow: 0 0 3mm yellow}</style></head>"
    "<body><h1>Hello, world!</h1></body></html>";
    SSL_write(ssl, html, strlen(html));

*/


    //SSL_shutdown(ssl); // SSL_free(ssl);
}








int main(int argc, char *argv[])
{
  SSL_METHOD *meth;
  SSL_CTX* ctx;
  SSL *ssl;
  int err;

  // Step 0: OpenSSL library initialization 
  // This step is no longer needed as of version 1.1.0.
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  // Step 1: SSL context initialization
  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  // Step 2: Set up the server certificate and private key
  SSL_CTX_use_certificate_file(ctx, "./cert_server/server-crt.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server-key.pem", SSL_FILETYPE_PEM);
  // Step 3: Create a new SSL structure for a connection
  ssl = SSL_new (ctx);

  struct sockaddr_in sa_client;
  size_t client_len;
  client_len=sizeof(sa_client);
  int listen_sock = setupTCPServer();
  int tunfd = createTunDevice();

  while(1){
    int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
    if (fork() == 0) { // The child process
       close (listen_sock);

       SSL_set_fd (ssl, sock);
       int err = SSL_accept (ssl);
       CHK_SSL(err);
       printf ("SSL connection established!\n");

       int result=processAuthentcation(ssl, sock);

      if(result==1){

    while(1){
    //int sock1 = accept(sock, (struct sockaddr*)&sa_client, &client_len);
    fd_set readFDSet;
    printf("after Accept");

         FD_ZERO(&readFDSet);
         FD_SET(tunfd, &readFDSet);
         FD_SET(sock, &readFDSet);
     
         select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

         if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sock,ssl);
         if (FD_ISSET(sock, &readFDSet))
         { 
          int output = socketSelected(tunfd, sock,ssl);
          if (output == -1) break;
         }
     }

     }else if(result==0){

    SSL_shutdown(ssl); 
    SSL_free(ssl);

    
    }
       
       
       close(sock);
       return 0;
    } else { // The parent process
        close(sock);
    }
  }

   
return 0;
}