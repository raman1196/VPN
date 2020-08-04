#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include "myheader.h"
#include <stdlib.h>
#include <termios.h>


#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client"
#define STDIN 0 

#define MAX_PASS 1024
int i;
ssize_t 
my_getpass (char *lineptr, size_t len, FILE *stream)        //Converts password to star
{
    struct termios old, new;
    int nread = 0;
    char c;
    
    /* Turn echoing off and fail if we can't. */
    if (tcgetattr (fileno (stream), &old) != 0)
    return -1;
    new = old;
    new.c_lflag &= ~ECHO || ECHOCTL;
    if (tcsetattr (fileno (stream), TCSAFLUSH, &new) != 0)
    return -1;
    /* Read the password. */
    getchar();
    while ((c = getchar()) != '\n' && nread + 1 < len) {
        lineptr[nread++] = c;
        printf("*");
    }
    printf("\n");
    lineptr[nread] = '\0';
    
    /* Restore terminal. */
    (void) tcsetattr (fileno (stream), TCSAFLUSH, &old);
    return nread;
}


int createTunDevice() {                                 //Creates interface to between Kernel and RClient program
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;                //IFF_TUN flag set 
    
    tunfd = open("/dev/net/tun", O_RDWR);               //open "dev/net/tun to use the driver"
    ioctl(tunfd, TUNSETIFF, &ifr);                      //Register TUN interface with the Kernel
    
    return tunfd;
}

void function_quit(int tunfd, int sockfd, SSL *ssl,char *hostname)
{
    printf("Quit called");    
    char sendBuf[100];    
    sprintf(sendBuf,"QUIT");
    SSL_write(ssl, sendBuf, strlen(sendBuf));
}

void tunSelected(int tunfd, int sockfd, SSL *ssl,char *hostname){       //Packet in the TUN Interface
    int  len;
    int BUFF_SIZE=2000;
    char buff[BUFF_SIZE];
    struct sockaddr_in peerAddr;

    //printf("Got a packet from TUN\n");
    
    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);  
    SSL_write(ssl, buff, len);
    
}


void socketSelected (int tunfd, int sockfd,SSL *ssl,char *hostname){    //Packet in the socket interface
    int BUFF_SIZE=2000;
    int  len;
    char buff[BUFF_SIZE];
    
    //printf("Got a packet from the tunnel\n");
    
    bzero(buff, BUFF_SIZE);
    //len = read(sockfd, buff, BUFF_SIZE);
    /* do {
        len = SSL_read (ssl, buff, sizeof(buff) - 1);
        buff[len] = '\0';
        printf("%s\n",buff);
        write(tunfd, buff, len);
    } while (len > 0); */
    len = SSL_read (ssl, buff, sizeof(buff));
    //printf("After SSL Read %s",buff);
    write(tunfd, buff, len);
    
}



int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);
    
    if (preverify_ok == 1) {
        printf("Verification passed.\n");
        } else {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        printf("Verification failed: %s.\n",
        X509_verify_cert_error_string(err));
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization 
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    
    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL* ssl;
    
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
        printf("Error setting the verify locations. \n");
        exit(0);
    }
    ssl = SSL_new (ctx);
    
    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);
    
    //X509_VERIFY_PARAM_set_hostflags(vpm, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    /*printf("%s",hostname);
        printf("%d------",sizeof(hostname));
        if (!X509_VERIFY_PARAM_set1_host(vpm, hostname, sizeof(hostname))) {
        // handle error
        return 0;
    }*/
    
    return ssl;
}


int setupTCPClient(const char* hostname, int port)
{
    struct sockaddr_in server_addr;
    
    // Get the IP address from hostname
    struct hostent* hp = gethostbyname(hostname);
    
    // Create a TCP socket
    int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    // Fill in the destination information (IP, port #, and family)
    memset (&server_addr, '\0' , sizeof(server_addr));
    memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    //server_addr.sin_addr.s_addr = inet_addr ("10.0.2.6"); 
    server_addr.sin_port   = htons (port);
    server_addr.sin_family = AF_INET;
    
    // Connect to the destination
    connect(sockfd, (struct sockaddr*) &server_addr,
    sizeof(server_addr));
    
    return sockfd;
}

/*
char* getPassword()
{
    char passinput[MAX_PASS];
    ssize_t n;
    printf("Password: ");
    n = my_getpass(passinput, sizeof(passinput), stdin);
    return passinput;
}*/


int main(int argc, char *argv[])
{
    char *hostname = "srivastavaVPN";
    int port = 6660;
    int tunfd;
    int flag=0;
    
    
    
    
    if (argc > 1) hostname = argv[1];
    if (argc > 2) port = atoi(argv[2]);
    
    
    /*------------------Get Username and Password --------*/
    
    char buf[1000];
       char sendBuf[200],sendBuf1[200];
       char logininput[40];    
    char passinput[MAX_PASS];
    
    
    //sprintf(sendBuf, "GET / HTTP/1.1\nHost: %s\n\n", hostname);
    //SSL_write(ssl, sendBuf, strlen(sendBuf));
    
    printf("\nEnter Username: ");
       scanf("%s",logininput);
    
    
    ssize_t n;
    printf("Enter Password: ");
    n = my_getpass(passinput, sizeof(passinput), stdin);
    
    
    
    
    tunfd  = createTunDevice();
    //----------------TLS initialization ----------------
    SSL *ssl   = setupTLSClient(hostname);
    
    //----------------Create a TCP connection ---------------
    int sockfd = setupTCPClient(hostname, port);
    
    
    
    //----------------TLS handshake ---------------------
    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl); CHK_SSL(err);
    printf("SSL connection is successful\n");
    printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
    
    //----------------Send/Receive data --------------------
    
    
    
    
    sprintf(sendBuf,logininput);
    SSL_write(ssl, sendBuf, strlen(sendBuf));
    
    
    
    
    sprintf(sendBuf1, passinput);
    SSL_write(ssl, sendBuf1, strlen(sendBuf1));
    
    
    int len=125;
    do {
        
        len = SSL_read (ssl, buf, sizeof(buf) - 1);
        buf[len] = '\0';
        
        //printf("%s\n",buf);
        //printf("\n%d-------",len);
        
        if(strcmp(buf,"success")==0){
            printf("\nAuthentication SuccessFul");
            flag=1;
            
            }else if(strcmp(buf,"failure")==0){
            
            printf("\nAuthentication Failure");
            flag=0;
            
        }
        
        
        break;
        
    } while (len > 0);
    
    //------------------------------Client On ------------
    
    
    
    
    if(flag==1){
        //printf("\nInto While Loop\n");
        while (1) {
            fd_set readFDSet;
            FD_ZERO(&readFDSet);
            FD_SET(tunfd, &readFDSet);
            FD_SET(sockfd, &readFDSet);
            FD_SET(STDIN,&readFDSet);
            
            select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
            if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd,ssl,hostname);
            if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd,ssl,hostname);
            if(FD_ISSET(STDIN,&readFDSet)) {function_quit(tunfd , sockfd , ssl , hostname); break;};
        }
        
        
    }
    
    close(sockfd);
    
    
    
    
    return 0;
}