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
#include <string.h>
#include <openssl/sha.h>
#include <math.h>
#include <fcntl.h> // open function
#include <unistd.h>
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
#define MAX_LEN 1024
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
 // long hashdigest;
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
Hdr hdr; /* Header for a message */
} Msg;

/* Function prototypes */
int serverConnect ( char * );
void Talk_to_server ( int );


/* RSA*/

typedef struct keys keys;
struct keys{
  long publickey_e;
  long privatekey_d;
  long key_n;
};

keys* get_RSA_keys;                                             //for client
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

p = rand_prime(50,500);
q = rand_prime(501,850);

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



/*RSA  */






/* Connect with the server: socket() and connect() */
int serverConnect ( char *sip )
{
   int cfd;
   struct sockaddr_in saddr;   /* address of server */
   int status;

   /* request for a socket descriptor */
   cfd = socket (AF_INET, SOCK_STREAM, 0);
   if (cfd == -1) {
      fprintf (stderr, "*** Client error: unable to get socket descriptor\n");
      exit(1);
   }

   /* set server address */
   saddr.sin_family = AF_INET;              /* Default value for most applications */
   saddr.sin_port = htons(SERVICE_PORT);    /* Service port in network byte order */
   saddr.sin_addr.s_addr = inet_addr(sip);  /* Convert server's IP to short int */     
   bzero(&(saddr.sin_zero),8);              /* zero the rest of the structure */

   /* set up connection with the server */
   status = connect(cfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr));
   if (status == -1) {
      fprintf(stderr, "*** Client error: unable to connect to server\n");
      exit(1);
   }

   fprintf(stderr, "Connected to server\n");

   return cfd;
}

/* Interaction with the server */
void Talk_to_server ( int cfd )
{
   // char buffer[MAX_LEN];
   int nbytes, status, flag=1;
   int src_addr, dest_addr;
   // char buffer[2];
    FILE *fp=NULL;
   ReqMsg send_msg;
   RepMsg recv_msg;
   PubKey pub_key_to_send;
   char character = ' ';
   dest_addr = inet_addr("DEFAULT_SERVER");
   src_addr = inet_addr("192.168.1.245");

   /* send the request message REQ to the server */
   printf("Sending the PUBKEY to the server\n");  

   pub_key_to_send.hdr.opcode = PUBKEY;
   pub_key_to_send.hdr.src_addr = src_addr;
   pub_key_to_send.hdr.dest_addr = dest_addr;
   pub_key_to_send.e = get_RSA_keys->publickey_e;
   pub_key_to_send.n = get_RSA_keys->key_n;

   // status = send(cfd, &send_msg, sizeof(ReqMsg), 0);
   status = send(cfd, &pub_key_to_send, sizeof(PubKey), 0);
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to send\n");
      return;
    }

    printf("Enter the file name:");
    scanf("%s",send_msg.filename);
    send_msg.disconnectflag = 0;
    printf("File name:%s sent!\n",send_msg.filename);
    status = send(cfd, &send_msg, sizeof(ReqMsg), 0);
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to send\n");
      return;
    }
    printf("Received:\t\tDecrypted:\tHash Calculated:\tReceived: \tStatus:\n");
      while (flag) {
      /* receive greetings from server */
       nbytes = recv(cfd, &recv_msg, sizeof(RepMsg), 0);
       if (nbytes == -1) {
          fprintf(stderr, "*** Client error: unable to receive\n");
          
       }
       switch ( recv_msg.hdr.opcode) {
        case REP:
                  
                  if(recv_msg.reqcom==0){
                    n = get_RSA_keys->key_n;
                    C=recv_msg.ciphertext;
                    d = get_RSA_keys->privatekey_d;

                    if (flag) {

                      decrypt();
                      
                      unsigned char thishash[SHA_DIGEST_LENGTH];
                      char text[2];
                      int i=0;
                        text[0] = M;
                        text[1] = '\0';
                        size_t length = sizeof(text);
                        SHA1((const unsigned char*)text, length, thishash);
                      
                        if(M>=1 && M<=25)
                            M += 64;
                        else if(M==0)                //space
                          M=32;
                        else if(M>=26 && M<=51)          //'a' to 'z'
                            M += 71;
                        else if(M>=52 && M<=60)
                            M -= 4;
                        else if(M==61)                  //,
                            M = 44;
                        else if(M==62)                  //.
                            M = 46;
                        else if(M==63)                  //!
                            M = 33;
                      printf("%li\t\t\t%c\t\t\t",C,(int)M);
                      i=0;
                      // for(i=0; i<1; i++){
                        if(thishash[i]!=recv_msg.hash[i]){
                          printf("Hash not Matched! Disconnecting!!!!\n");
                          recv_msg.reqcom=3;
                          // hasherror = 1;
                          break;
                        }
                        else if(thishash[i]==recv_msg.hash[i])
                          printf("%d\t\t%d\t\t",thishash[i],recv_msg.hash[i]);
                          printf("Hash matched!\n");
                      // }
                      
                      character = M;

                        char buffer[2] = {character, '\0'};

                       fp = fopen(send_msg.filename, "a");
                       if(character>=0  && (character==9 || (character>31 && character<127) ))
                        fprintf(fp,"%s", buffer);
                       fclose(fp);
                    }
                  }
                  
                  else if(recv_msg.reqcom==1 || recv_msg.reqcom==3){                     //reqcom message
                      if(recv_msg.reqcom==1){
                      printf("File Received!\nDisconnect Request sent!\n");
                      send_msg.disconnectflag = 1;                //to disconnect from the server

                      status = send(cfd, &send_msg, sizeof(ReqMsg), 0);
                       if (status == -1) {
                          fprintf(stderr, "*** Server error: unable to send\n");
                          return;
                        }

                        nbytes = recv(cfd, &recv_msg, sizeof(RepMsg), 0);
                         if (nbytes == -1) {
                            fprintf(stderr, "*** Client error: unable to receive\n");
                            
                         }
                        if(recv_msg.disconnectflag==1)
                          printf("Disconnect request completed!\n");   
                      }

                      flag=0;
                  }

                  else if(recv_msg.reqcom==2){
                    printf("File doesn't exists!\nDisconnect request completed!\n");
                    flag=0;
                  }

                  break;
       default: 

               flag =0;
               break;  
       }
     }//end of while
}

int main ( int argc, char *argv[] )
{
   char sip[16];
   int cfd;
   

   printf("******* Client Started ***** \n\n");
   
   get_RSA_keys = mainOfRSA();

   strcpy(sip, (argc == 2) ? argv[1] : DEFAULT_SERVER);
   cfd = serverConnect(sip);
   Talk_to_server (cfd);
   close(cfd);                               //---------------------
   return 0;
}

/*** End of client.c ***/
