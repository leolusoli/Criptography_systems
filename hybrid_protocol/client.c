//Per compilare: gcc -ggdb -Wall -Wextra -o server server.c -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <base64.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>



//Costanti per la comunicazione, per Default è all'indirizzo localhost e la porta è la 25001
#define SERVER "127.0.0.1"
#define BUFLEN 2048
#define PORT 25001

//Definisco il padding per settare il tipo di RSA crypt e RSA decrypt.
int padding = RSA_PKCS1_PADDING;

					// ----------------- AES -------------------------//

//Utilizzeremo AES in Counter Mode (CTR). Si ulizzerà un IV(Inizialitation Vector), ovvero una parola di 16 bits dove 8 sono
//randomizzati e gli altri contengono un contatore del frammento di file che si sta criptando decriptando. Quando si dovrà
//la cifratura, i bit della frammento corrente saranno XOR-modellati con IV e stessa cosa per il decrypt rendendo le operazioni
//velocissime. L'IV verrà memorizzato nel File criptato, e quindi si potrà si estrarre in fase di decrypt.

//Variabile che conterrà la password per AES randomizzata ogni volta che si crypta un file.
unsigned char password[16];

//stringarandomi per i nomi criptati dei file
//char rnd_string[19];

//Defiamo una struct che conterrà le informazioni dell'IV:
//ivec : il nostro vettore di byte che costituisce l'iv.
//num, ecount : sono variabili che saranno passate alla funzione di encrypt.
//AES_BLOCK_SIZE : sarà un valore integer 16. Stiamo infatti utilizziamo la modalità a 128 bit.
struct ctr_state {
  unsigned char ivec[AES_BLOCK_SIZE];
  unsigned int num;
  unsigned char ecount[AES_BLOCK_SIZE];
};

//Stream file per il file originale e per il file criptato.
FILE *readFile;
FILE *writeFile;

//Inizializzazione della chiave AES.
AES_KEY key;


//quanti byte dobbiamo leggere/scrivere ogni che operiamo.
int bytes_read, bytes_written;

//l'informazione che dobbiamo leggere/scrivere dal file.
unsigned char indata[AES_BLOCK_SIZE];
unsigned char outdata[AES_BLOCK_SIZE];

//l'IV che dobbiamo leggere dal file.
unsigned char iv[AES_BLOCK_SIZE];

//la struttura ctr_state che utilizzeremo per criptare.
struct ctr_state state;

// è utile avere una funzione che inizializzi le propietà dell'IV con
// con il valore 0 eccetto i primi 8 byte che conterranno un input random

void init_ctr(struct ctr_state *state, const unsigned char iv[16]) {
  
  /* aes_ctr128_encrypt (funzione di libreria openssl) necessita 'num' e 
     'ecout' settati a zero al momento della prima chiamata */

	state->num = 0;
  	memset(state->ecount, 0, AES_BLOCK_SIZE);

  /* inizializzo il counter in 'ivec' a 0 */

 	memset(state->ivec+8, 0, 8);

  /* copio l'iv in 'ivec' */

 	memcpy(state->ivec, iv, 8);
}

// fencrypt : funzione che esegue la crifratura AES

/*

  read : Il file da criptare.

  write : Il file criptato.

  enc_key : la passowrd utilizzata per creare la chiave usata per criptare il file (deve essere lunga 16 bytes. Questa è la 	  password del file)

*/

void fencrypt(char* read, char* write, const unsigned char* enc_key)
{ 
  	//calcoliamo la parte random dell'IV
	if(!RAND_bytes(iv, AES_BLOCK_SIZE)) {
      		fprintf(stderr, "Non è stato possibile randomizzare l'IV.");
      		exit(1);    
    	}
  	
	//Apriamo il file di lettura e quello di scrittura
  	readFile = fopen(read,"rb"); // The b è richiesto in Windows.
  	writeFile = fopen(write,"wb");
  
  	if(readFile==NULL) {
      		fprintf(stderr, "Impossibile aprire il file di lettura"); 
      		exit(1);
    	}
  
  	if(writeFile==NULL) {
      		fprintf(stderr, "Impossibile creare il file in cui scrivere la codifica"); 
      		exit(1);
    	}
  
  	//scriviamo i primi 8 byte dell'iv con i byte appena randomizzati
  	fwrite(iv, 1, 8, writeFile);
  	//rempiamo i byte da 9 a 16 con dei Byte nulli
  	fwrite("\0\0\0\0\0\0\0\0", 1, 8, writeFile); 
  
  	//Inizializziamo la chiave AES che andremo a utilizzare
  	if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
      		fprintf(stderr, "Impossibile creare la chiave di cifratura AES");
      		exit(1); 
    	}

  	//chiamiamo la init, che ci permette di inzializzare la struttura ctr
  	init_ctr(&state, iv);
  
  	//Criptiamo il file finche non è finito, e scriviamo il contenuto nel file di output	
  	while(1){
		bytes_read = fread(indata, 1, AES_BLOCK_SIZE, readFile); 
	  	AES_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);
	  
	 	bytes_written = fwrite(outdata, 1, bytes_read, writeFile); 
	  	if (bytes_read < AES_BLOCK_SIZE){
	        	break;
	   	}
	}
  
  	fclose(writeFile);
  	fclose(readFile);

}


// fencrypt : funzione che esegue la crifratura AES

/*

  read : Il file da decriptare.

  write : Il file ripristinato.

  enc_key : la passowrd utilizzata per creare la chiave usata per decriptare il file (deve essere lunga 16 bytes. Questa è la 	  password del file, deve essere la stessa usata nella cifratura)

*/

void fdecrypt(char* read, char* write, const unsigned char* enc_key){	

	readFile=fopen(read,"rb"); // b è richiesto in ambiente windows
  	writeFile=fopen(write,"wb");

  	if(readFile==NULL){
    		fprintf(stderr,"Errore durante l'apertura del file di lettura");
   		exit(1);
  	}

  	if(writeFile==NULL){
   		fprintf(stderr, "Errore durante l'apertura del file di scrittura");
    		exit(1);
  	}

  	fread(iv, 1, AES_BLOCK_SIZE, readFile);

  	//Inizzializzazione della chiave AES
  	if (AES_set_encrypt_key(enc_key, 128, &key) < 0){
  		fprintf(stderr, "Could not set decryption key.");
   		exit(1);
  	}
  
  	//Chiamata la counter
  	init_ctr(&state, iv);
  
  	//Crittografia simmetrica, decriptiamo con la stesso chiper il file precedentemente criptato nello stesso modo.
  	while(1) {
    		bytes_read = fread(indata, 1, AES_BLOCK_SIZE, readFile);
    		AES_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);

    		bytes_written = fwrite(outdata, 1, bytes_read, writeFile);
    		if (bytes_read < AES_BLOCK_SIZE) {
       			break;
       		}	
     	}
    	fclose(writeFile);
    	fclose(readFile); 

}

// Crea una Parola di 16 byte random, verrà utilizzata come password per creare la chiave.

void create_aes_password() {

  //pulisco la stringa dove salverà il chiper di AES corrente
  strcpy((char *)password,"");
  if(!RAND_bytes(password, 16)) {
     fprintf(stderr, "Impossibile creare bytes random per la password");
     exit(1);
  }
  printf("\n%s", password);
}

					// ------------ RSA CRYPT PHASE ----------- //

/*

  In questa parte definiamo le funzioni che ci permetteranno di criptare la password di AES con la chiave pubblica
  creata dal server, e di decriptarla più tardi se il Client lo vuole.

*/

//Funzione che permette di ottenre correttamente le chiavi incapsulate nel pacchetto ricevuto dal server.
RSA * createRSA(const char * key, int public) {

	//Creo uno Stream di lettura per una chiave RSA. L'opzione -1 assume che la stringa sia NULL terminated. 
	BIO* keybio = BIO_new_mem_buf((void*)key, -1);
	//Imposta la configurazione di lettura dei caratteri che verranno letto dallo stream (Base 64, non null).
  	BIO_set_flags(keybio, BIO_FLAGS_BASE64_NO_NL);
	//Definisco una struttra RSA, pronta a contenere una chiave
  	RSA * rsaKey;
	//Se il secondo parametro della funzione è 1, allora il Client deve memorizzare la chiave pubblica, mentre invece
	//se il parametro è 0, allora il Client deve memorizzare la chiave privata.
  	if (public) {
		//PER_read_bio_RSA_PUBKEY legge un BIO contenente una chiave pubblica in formato PEM. Il formato è giusto
		//in quanto nel processo di creazione del Server, la chiave pubblica è stata creata in modo tale da rispettare il 
		//formato PEM. Per la chiave privata avremo un formato differente. Ho fatto ciò per dimostrare il fatto che non è
		//un problema utilizzare formati diversi, l'importante è che le chiavi siano corrette.
  		rsaKey = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL );
		//Se il processo non va a buon fine, stampo a video l'errore con ERR_error_string.
  		if(!rsaKey) {
    			printf("ERROR: Could not load PUBLIC KEY!  PEM_read_bio_RSA_PUBKEY FAILED: %s\n", ERR_error_string(ERR_get_error(), NULL));
		}
  	} else {
		//PEM_read_bio_RSAPrivateKey legge un BIO contenente una chiave privata in formato PKCS#1. Il formato è giusto in
		//quanto nel processo di creazione del Server, a chiave privata è stata creata in modo tale da rispettare 
		//il formato PKCS#1. 
		rsaKey = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL );
		//Se il processo non va a buon fine, stampo a video l'errore con ERR_error_string.
		if(!rsaKey) {
    			printf("ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSA_RSAPrivateKey FAILED: %s\n", ERR_error_string(ERR_get_error(), NULL));
		}
  	}
	//Libero lo stream di lettura della chiave e ritorno la chiave RSA.
  	BIO_free(keybio);
  	return rsaKey;
}

//Funzione che prende in input la password utilizzata per eseguire la cifratura AES e la chiave
//pubblica RSA ed esegue la cifratura della password AES con la chiave pubblica RSA.
int public_rsa_encrypt(unsigned char * data, int data_len, RSA * key, unsigned char * encrypted) {

	//RSA_public_encrypt esegue la cifratura di data di lunghezza data_len utilizzando la chiave pubblica key e memorizza
	//il risultato in encrypted. Utilizziamo il padding di base settatto ad inizio programma. Se la funzione non va a
	//buon fine result è uguale a 0.
	int result = RSA_public_encrypt(data_len, data, encrypted, key, padding);
	return result;

}

//Funzione che prende in input la password aes cifrata  e la chiave privata RSA ed esegue la decifratura 
//della password AES criptata, utilizzando la chiave privata RSA.
int private_rsa_decrypt(unsigned char * enc_data, int data_len, RSA * key, unsigned char * decrypted) {
    
	//RSA_private_decrypt esegue la decifratura di enc_data di lunghezza data_len utilizzando la chiave priavata key
	// e memorizz il risultato in decrypted. Utilizziamo il padding di base settatto ad inizio programma 
	//(uguale alla cifratura). Se la funzione non va a buon fine result è uguale a 0.
	int result = RSA_private_decrypt(data_len, enc_data, decrypted, key, padding);
	return result;
}

//Funzione che setta il processo di ricezione della chiave pubblica dal Server
RSA * network_communication_receive_pbk(){

	//Inizializzazione delle strutture per la comunicazione tramite socket.
  	struct sockaddr_in socket_server;
  	int s;
  	socklen_t slen=sizeof(socket_server);

	//Conterrà il messaggio identificativo della funzione del client
	char message[5];
	//Conterrà il messaggio da spedire.
  	char buf[BUFLEN];

  	//socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) crea un endpoint per la comunicazione(UDP a datagrammi con indirizzi IPv4) e
	//ritorna un file descriptor che descrive la comunicazione appena creata.
  	if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
     		printf("errore nella creazione del socket");
    	}
    
	//Preparo la struttura che dovrà contenere il Socket, settando la porta e varie configurazioni.
  	memset((char *) &socket_server, 0, sizeof(socket_server));
  	socket_server.sin_family = AF_INET;
  	socket_server.sin_port = htons(PORT);
     
	//Controllo se l'indirizzo del Server è quello corretto.
  	if (inet_aton(SERVER , &socket_server.sin_addr) == 0){
        	fprintf(stderr, "inet_aton() failed\n");
     		exit(1);
    	}

  	//Start è l'identificativo che indica l'esigenza da parte del Client di avere dal Server una chiave Pubblica.
 	strcpy(message,"start");
  
  	//Mando il messaggio al Server.
  	if (sendto(s, message, strlen(message) , 0 , (struct sockaddr *) &socket_server, slen)==-1) {
      		printf("errore nell'invio");
    	}
		
  	while(1) {       
    		//Il client si mette in attesa della risposta del Server.
    		//Puliamo il buffer, cosi da evitare errori di sovrascrittura
    		memset(buf,'\0', BUFLEN);
    
    		//Ricevo la chiave pubblica dal server che sarà salvata nella variabile buff.
    		if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &socket_server, &slen) == -1){
			printf("errore nella ricezione");
      		}
        
		//Stampo la chiave pubblica ricevuta.
    		puts(buf);
		//Esco dal ciclo.
    		break;
    
  	}
	
 	//Chiudo la communicazione con il Server
  	close(s);
	//Sfrutto la funzione createRSA per ricavare la messaggio ricevuto, la chiave pubblica pronta per essere utilizzata.
  	RSA * pubkey = createRSA(buf,1);
	//Ottenuta la chiave pubblica la ritorno al Main.
  	return pubkey;

}

//Funzione che setta il processo di ricezione della chiave privata dal Server
RSA * network_communication_receive_pvk(){

	//Inizializzazione delle strutture per la comunicazione tramite socket.
	struct sockaddr_in socket_server;
  	int s;
  	socklen_t slen=sizeof(socket_server);

	//Conterrà il messaggio da spedire.
  	char buf[BUFLEN];
	//Conterrà il messaggio identificativo della funzione del client
	char message[5];

  	//socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) crea un endpoint per la comunicazione(UDP a datagrammi con indirizzi IPv4) e
	//ritorna un file descriptor che descrive la comunicazione appena creata.
 	if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
     		printf("errore nella creazione del socket");
    	}
    	
	//Preparo la struttura che dovrà contenere il Socket, settando la porta e varie configurazioni.
  	memset((char *) &socket_server, 0, sizeof(socket_server));
  	socket_server.sin_family = AF_INET;
  	socket_server.sin_port = htons(PORT);
     
  	if (inet_aton(SERVER , &socket_server.sin_addr) == 0){
     		fprintf(stderr, "inet_aton() failed\n");
       		exit(1);
   	}

  	//Paid è l'identificativo che indica l'esigenza da parte del Client di avere dal Server una chiave Privata. 
  	strcpy(message,"paid\0");
  
  	//Mando il messaggio al Server
  	if (sendto(s, message, strlen(message) , 0 , (struct sockaddr *) &socket_server, slen)==-1){
        	printf("errore nell'invio");
    	}
	
  	while(1) {       
    		//Il Client si mette in attesa della risposta del Server.
    		//Puliamo il buffer, cosi da evitare errori di sovrascrittura.
    		memset(buf,'\0', BUFLEN);
    
    		//Ricevo la chiave privata dal server che sarà salvata nella variabile buff
    		if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &socket_server, &slen) == -1){
			printf("errore nella ricezione");
      		}
         
		//Stampo la chiave privata ricevuta.
    		puts(buf);
		//Esco dal ciclo
    		break;
    
  	}

  	//Chiudo la communicazione con il Server
  	close(s);
	//Sfrutto la funzione createRSA per ricavare dal messaggio ricevuto, la chiave privata pronta per essere utilizzata.
  	RSA * privkey = createRSA(buf,0);
	//Ottenuta la chiave privata la ritorno al Main.
  	return privkey;

}


int main() {
	char name_file[256];
	char enter = 0;
  	RSA * pubkey = NULL;
  	RSA * privkey = NULL;
  	unsigned char encrypted[4098]={};
  	unsigned char restored[4098]={};
  	srand( (unsigned)time( NULL ) );
  	printf("passo 1. Chiediamo all'utente che file si vuol criptare");
	printf("\n");
	printf("Inserisci l'indirizzo del file da criptare:  ");
	printf("\n");
	scanf("%s",name_file);
	printf("\n");
	printf("passo 2. Creiamo la password AES con un generatore di numeri casuali.");
  	create_aes_password();
  	printf("\n");
	printf("Premi invio per continuare");
	enter = 0;
	while (enter != '\r' && enter != '\n') { enter = getchar(); }
	printf("\n");
  	printf("passo 3. Criptiamo il file con l'algoritmo AES in modalità CRT");
	printf("\n");
  	fencrypt((char *)name_file, "criptato.enc", (unsigned const char*)password);
	printf("Premi invio per continuare");
	enter = 0;
	while (enter != '\r' && enter != '\n') { enter = getchar(); }
	printf("\n");
  	printf("passo 4. Richiediamo al Server una chiave pubblica");
	printf("\n");
	printf("\n");
  	pubkey = network_communication_receive_pbk();
	printf("\n");
	printf("Premi invio per continuare");
	enter = 0;
	while (enter != '\r' && enter != '\n') { enter = getchar(); }
	printf("\n");
  	printf("passo 5. Criptiamo la password utilizzata dall'algoritmo AES.");
	printf("\n");
  	int encrypted_l = public_rsa_encrypt(password, strlen((char*)password), pubkey, encrypted);
  	if(encrypted_l == -1) {
  		printf("public encrypt failed");
  	} 
  	printf("%s\n",encrypted);
	printf("\n");
	printf("Premi invio per continuare");
	enter = 0;
	while (enter != '\r' && enter != '\n') { enter = getchar(); }
	printf("\n");
  	printf("passo 6. Richiediamo la chiave privata per poter decriptare la password AES");
	printf("\n");
	printf("\n");
  	privkey = network_communication_receive_pvk();
	printf("\n");
	printf("Premi invio per continuare");
	enter = 0;
	while (enter != '\r' && enter != '\n') { enter = getchar(); }
	printf("\n");
	printf("passo 7. Ottenuta la password, decriptiamo la password criptata.");
	printf("\n");
  	int decrypted_l = private_rsa_decrypt(encrypted, encrypted_l, privkey, restored);
  	if(decrypted_l == -1) {
  		printf("public decrypt failed");
  	}
  	printf("%s\n",restored);
	printf("Premi invio per continuare");
	enter = 0;
	while (enter != '\r' && enter != '\n') { enter = getchar(); }
	printf("\n");
	printf("passo 8. Controllo se la password è uguale alla precedente è compio il decrypt del file.");
	printf("\n");
  	if (strcmp(password, restored) == 0) {
		printf("La password è la stessa");
  	}
	printf("\n");
  	fdecrypt("criptato.enc", "restored.txt", (unsigned const char*)restored);
	printf("\n");
	printf("Fine elaborazione");
  	return 0;
}
