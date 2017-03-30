/*****************************************************************************
 *** Program explaining the client-server model                            ***
 *** developed by Ashok Kumar Das, CSE Department, IIT Kharagpur           ***
 ***                                                                       ***
 *****************************************************************************/

/****************************************************************************
Problem: User A (client) sends the request message REQ to the user B (server).
In response, user B (server) replies the response message REP to the user A
(client).
REQ contains:
1. message header
2. integer x
3. integer y
4. integer check1 = x AND y
5. integer check2 = x XOR y

REP contains:
1. message header
2. integer status: 1 (SUCCESS) and 0 (FAIL)
if both check1 and check2 are valid, then return 1;
else return 0.
*******************************************************************************/ 


#include <stdio.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <string.h>
#include <fcntl.h> // open function
#include <unistd.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

// #include "rsaalgorithm.c"

/* Global constants */
#define SERVICE_PORT 41089
#define MAX_SIZE 20
#define Q_SIZE 5

#define SUCCESS 1
#define FAIL 0


#define DEFAULT_SERVER "192.168.1.241"

#define REQ 20  /* Request message */
#define REP 30  /* Reply message */
#define PUBKEY 10 /*RSA Public key to send */

/* Define a message structure */
typedef struct {
 int opcode;
 int src_addr;
 int dest_addr;
 } Hdr;

/* REQ message */
typedef struct {
 Hdr hdr;
 int x;
 int y;
 int check1; /* x AND y */
 int check2; /* x XOR y */
 char filename[50];
 int disconnectflag;
} ReqMsg;

/* REP message */
typedef struct {
 Hdr hdr;
 long ciphertext;
 int reqcom;
 unsigned char hash[SHA_DIGEST_LENGTH];
 int status;
 int disconnectflag;
} RepMsg;

/* RSA public key */
typedef struct {
Hdr hdr;
long e; /* encryption exponent */
long n; /* modulus */
} PubKey;

/*A general message */
typedef struct {
// AllMsg allmsg;
Hdr hdr; /* Header for a message */
} Msg;



/* Function prototypes */
int startServer ( );
void Talk_to_client ( int );
void serverLoop ( int );



/*RSA */
typedef struct keys keys;
struct keys{
  long publickey_e;
  long privatekey_d;
  long key_n;
};

long phi,M,n,e,d,C,FLAG;

int check()
{
// int i;
// for(i=3;e%i==0 && phi%i==0;i+2)
// {
// FLAG = 1;
// break;
// }
FLAG = 0;
return FLAG;
}

void encrypt()
{
long i;
C = 1;
for(i=0;i< e;i++)
  C=C*M%n;
C = C%n;
// printf("\n\tEncrypted keyword : %li",C);
}

void decrypt()
{
long i;
M = 1;
for(i=0;i< d;i++)
M=M*C%n;
M = M%n;
// printf("\n\tDecrypted keyword : %li",M);
}

/* generate prime number*/

int isprime(unsigned long n) {
  /*if((n&1)==0) return n==2;*/
  if(n%3==0) return n==3;
  /*if(n<25) return n>1;*/
  unsigned long p = 5;
  while (p*p <= n) {
    if (n%p==0) return 0;
    p += 2;
    if (n%p==0) return 0;
    p += 4;
  }
  return 1;
}

unsigned long rand_prime(int lower, int upper) {
  unsigned long spread = upper - lower + 1;
  while(1) {
    unsigned long p = 1 | (rand() % spread + lower);
    if (isprime(p)) return p;
  }
}

/* generate prime number*/

keys* mainOfRSA()
{
int p,q,s;
keys *returnthiskey = (keys*)malloc(sizeof(keys));
// clrscr();

p = rand_prime(50,5000);
q = rand_prime(501,8500);

n = p*q;
phi=(p-1)*(q-1);
// printf("\n\tF(n) phi value\t= %li",phi);
do
{
e = rand_prime(phi/2,phi);

// check();
}while(FLAG==1);
d = 1;
do
{
s = (d*e)%phi;
d++;
}while(s!=1);
d = d-1;
// printf("\n\tPublic Key\t: {%lli,%lli}",e,n);
// printf("\n\tPrivate Key\t: {%lli,%lli}",d,n);
// printf("\n\nEnter The Plain Text\t: ");
// scanf("%d",&M);
// encrypt();
// printf("\n\nEnter the Cipher text\t: ");
// scanf("%d",&C);
// decrypt();

returnthiskey->publickey_e = e;
returnthiskey->privatekey_d = d;
returnthiskey->key_n = n;
return returnthiskey;
// getch();
// return 0;
}

/* RSA*/



/* Start the server: socket(), bind() and listen() */
int startServer ()
{
   int sfd;                    /* for listening to port PORT_NUMBER */
   struct sockaddr_in saddr;   /* address of server */
   int status;


   /* Request for a socket descriptor */
   sfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sfd == -1) {
      fprintf(stderr, "*** Server error: unable to get socket descriptor\n");
      exit(1);
   }

   /* Set the fields of server's internet address structure */
   saddr.sin_family = AF_INET;            /* Default value for most applications */
   saddr.sin_port = htons(SERVICE_PORT);  /* Service port in network byte order */
   saddr.sin_addr.s_addr = INADDR_ANY;    /* Server's local address: 0.0.0.0 (htons not necessary) */
   bzero(&(saddr.sin_zero),8);            /* zero the rest of the structure */

   /* Bind the socket to SERVICE_PORT for listening */
   status = bind(sfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr));
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to bind to port %d\n", SERVICE_PORT);
      exit(2);
   }

   /* Now listen to the service port */
   status = listen(sfd,Q_SIZE);
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to listen\n");
      exit(3);
   }

   fprintf(stderr, "+++ Server successfully started, listening to port %hd\n", SERVICE_PORT);
   return sfd;
}


/* Accept connections from clients, spawn a child process for each request */
void serverLoop ( int sfd )
{
   int cfd;                    /* for communication with clients */
   struct sockaddr_in caddr;   /* address of client */
   socklen_t size;


    while (1) {
      /* accept connection from clients */
      cfd = accept(sfd, (struct sockaddr *)&caddr, &size);
      if (cfd == -1) {
         fprintf(stderr, "*** Server error: unable to accept request\n");
         continue;
      }
     
      /* fork a child to process request from client */
      if (!fork()) {                         //--------------
         Talk_to_client (cfd);
         // fprintf(stderr, "**** Closed connection with %s\n", inet_ntoa(caddr.sin_addr));
         fprintf(stderr, "**** Closed connection with the Client!\n");
         close(cfd);
         exit(0);
      }

      /* parent (server) does not talk with clients */
      close(cfd);

      /* parent waits for termination of child processes */
      while (waitpid(-1,NULL,WNOHANG) > 0);
   }
}


/* Interaction of the child process with the client */
void Talk_to_client ( int cfd )
{
   int status;
   int nbytes;
   int src_addr, dest_addr, printflag=0;
   // int chk1, chk2; 
   RepMsg send_msg;
   ReqMsg recv_msg;
   PubKey public_key_got;

   dest_addr = inet_addr("192.168.1.245");
   src_addr = inet_addr("DEFAULT_SERVER");
 
   // while (1) {
   /* Receive response from server */
   nbytes = recv(cfd, &public_key_got, sizeof(PubKey),0);
   if (nbytes == -1) {
      fprintf(stderr, "*** Server error: unable to receive\n");
      return;
   }
   
   // switch ( recv_msg.hdr.opcode ) {
   switch ( public_key_got.hdr.opcode ) {
    
   case PUBKEY : /* Request message */
              printf("Message:: with opcode 10 (PUBKEY) received from source (%d)\n", recv_msg.hdr.src_addr);  
              send_msg.hdr.opcode = REP;
              send_msg.hdr.src_addr = src_addr;        
              send_msg.hdr.dest_addr = dest_addr;  
              send_msg.disconnectflag = 0;
              printf("Received values in PUBKEY message are: \n");
              printf("e = %li\n", public_key_got.e);
              printf("n = %li\n", public_key_got.n);
              
              printf("Sending the reply message REP to the client \n"); 
              status = send(cfd, &send_msg, sizeof(RepMsg), 0);
               if (status == -1) {
                fprintf(stderr, "*** Client error: unable to send\n");
                return;
                }
              break;
    default: 
           printf("message received with opcode: %d\n", recv_msg.hdr.opcode);
           exit(0);  
   }


   while(1){

    nbytes = recv(cfd, &recv_msg, sizeof(ReqMsg),0);
   if (nbytes == -1) {
      fprintf(stderr, "*** Server error: unable to receive\n");
      return;
   }
   if (recv_msg.disconnectflag==0){                      //file name received
              struct stat st;
              // char characters[4];
              // int index=0;
              if(stat(recv_msg.filename, &st)==0)
             {

               send_msg.hdr.opcode = REP;
              printf("File exits..\n Plaintext:\t\tCiphertext:\tHash Sent:\n");
              char ch;
              // long int k,en;
              FILE *fp;
              fp = fopen (recv_msg.filename,"r");

                while(ch!=EOF){
                  ch = fgetc(fp);
                  // printf("%c",ch);
                  printf("%c\t\t",ch);
                  if(ch>=65 && ch<=90)
                      ch -= 64;
                  else if(ch==32)                //space
                    ch=0;
                  else if(ch>=97 && ch<=122)          //'a' to 'z'
                      ch -= 71;
                  else if(ch>=48 && ch<=57)
                      ch += 4;
                  else if(ch==44)                  //,
                      ch = 61;
                  else if(ch==46)                  //.
                      ch = 62;
                  else if(ch==33)                  //!
                      ch = 63;

                  e = public_key_got.e;
                  M = ch;
                  n = public_key_got.n;

                  encrypt();
                  
                    char text[2];
                    text[0] = ch;
                    text[1] = '\0';
                    size_t length = sizeof(text);
                    SHA1((const unsigned char*)text, length, send_msg.hash);

                    printf("%li\t\t%li\n",C,(long int)send_msg.hash);
                    // printf("Sending the ciphertext message REP to the client:%li \n",C); 
                    send_msg.ciphertext = C;
                    send_msg.reqcom = 0;
                    status = send(cfd, &send_msg, sizeof(RepMsg), 0);
                     if (status == -1) {
                      fprintf(stderr, "*** Server error: unable to send\n");
                      return;
                      }
                  }
                  send_msg.reqcom = 1;
              }

              if (stat(recv_msg.filename, &st)!=0 || send_msg.reqcom ==1){

                    if(stat(recv_msg.filename, &st)!=0 && printflag==0){
                      printf("File doesn't exists ! Sending disconnect message to the client!\n");
                      send_msg.reqcom = 2;
                      printflag=1;
                    }
                    else
                      send_msg.reqcom = 1;
                    status = send(cfd, &send_msg, sizeof(RepMsg), 0);
                     if (status == -1) {
                      fprintf(stderr, "*** Server error: unable to send\n");
                      return;
                      }
              }
        }

      else if(recv_msg.disconnectflag==1){
        printf("Disconnect request received by the server!\n");
          send_msg.disconnectflag=1;
          printf("Sending Disconnect grant to the client!\n");
          status = send(cfd, &send_msg, sizeof(RepMsg), 0);
           if (status == -1) {
            fprintf(stderr, "*** Client error: unable to send\n");
            return;
            }
            break;
      }

   }  // end of while
}

int main ()
{
   int sfd;
   sfd = startServer();   
   serverLoop(sfd);
   return 0;
}

/*** End of server.c ***/     

