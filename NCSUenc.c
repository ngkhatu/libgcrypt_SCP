#include <sys/socket.h>     // definitions of structures needed for sockets
#include <sys/types.h>      // definitions of data types used in system calls
#include <netinet/in.h>     // constants and structures needed for internet domain addresses
//#include <arpa/inet.h>      // definitions for internet operations
#include <unistd.h>         // defines misc. symbollic constants and types. Declares misc. functions
#include <errno.h>          // defines macros to report error conditions through error codes in static location
#include <netdb.h>          // definitions of network database operations
/*****************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gcrypt.h>

gcry_cipher_hd_t handle ;
gcry_md_hd_t hmac_handle ;
//gcry_error_t err = 0 ;
FILE *input_file ;
FILE *output_file ;
char input_file_name[50] = "\0" ;
char output_file_name[50] = "\0" ;

struct hostent *host;
struct sockaddr_in server_addr;         // socket address info for many types of sockets (but mainly for IPv4)
char second_arg[50] = "\0" ;
char port_string[50] = "\0" ;
int port_int ;
char ip_address[20] = "\0" ;
int sock, i ;
unsigned char data_buffer[16] ;

char password[50] = "checkpass\0" ;
char salt[32] ;
char IV[16] ;
unsigned char password_key[32] ;
char hmac_key[16] ;

void transmit_encrypted(void) ;
void store_encrypted(void) ;
void init_gcrypt_lib(void) ;
int main(int argc, char* argv[]) ;


void transmit_encrypted(){

    int file_size;
    int size_processed = 0 ;
    char ack[4] ;

    // Setup socket: socket() --> IPv4, stream, TCP
    host = gethostbyname(ip_address) ;
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) perror("Socket");
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_int);
    server_addr.sin_addr = *((struct in_addr *)host->h_addr);
    //bzero() - sets n bytes to 0 at memory location specified
    bzero(&(server_addr.sin_zero),8);
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) perror("Connect");

    // Get file size and send
    fseek(input_file, 0L, SEEK_END);
    file_size = ftell(input_file);
    fseek(input_file, 0L, SEEK_SET);
    send(sock,output_file_name, 50, 0) ;

    // Send file size and file name
    send(sock, &file_size, sizeof(int), 0) ;


    // Start transmitting Data
    while(file_size > size_processed)
        {

        // Read data
        fread(data_buffer, 1, 16, input_file) ;

        // Update HMAC
        gcry_md_write(hmac_handle, data_buffer, 16) ;
        gcry_md_reset(hmac_handle) ;

        // Encrypt data
        gcry_cipher_encrypt(handle, data_buffer, 16, NULL, 0) ;
        gcry_cipher_reset(handle) ;

        // Send data to server and wait for ack
        if (send(sock, data_buffer, 16, 0) == -1) perror("Send error!\n") ;
        while(recv(sock, ack, 4, 0)) if (ack[0] == 'A' && ack[1] == 'C' && ack[2] == 'K' && ack[3] == '\0') break ;

        // Increment
        size_processed += 16 ;
        }

    // Send HMAC
    send(sock, gcry_md_read(hmac_handle, GCRY_MD_SHA512), 64, 0) ;

    // Print HMAC for testing
/*  printf("HMAC:");
    for(i = 0; i < 64; i++)putchar(*(gcry_md_read(hmac_handle, GCRY_MD_SHA512)+i)) ;
    printf("\n");
*/
}


void store_encrypted()
{
    int file_size ;
    int size_processed = 0;

    // Get file size
    fseek(input_file, 0L, SEEK_END);
    file_size = ftell(input_file);
    fseek(input_file, 0L, SEEK_SET);

    // Write size to file
    fwrite(&file_size, 1, sizeof(int), output_file) ;

    // Encrypt, write to file
    while(file_size > size_processed)
        {
        // Read data from input file
        fread(data_buffer, 1, 16, input_file) ;

        // Update HMAC
        gcry_md_write(hmac_handle, data_buffer, 16) ;
        gcry_md_reset(hmac_handle) ;

        // Encrypt data in buffer
        gcry_cipher_encrypt(handle, data_buffer, 16, NULL, 0) ;
        gcry_cipher_reset(handle) ;

        // Write encryped to output file
        fwrite(data_buffer, 1, 16, output_file) ;

        // Increment
        size_processed += 16 ;
        }

    // Write HMAC to file
    fwrite(gcry_md_read(hmac_handle, GCRY_MD_SHA512), 1, gcry_md_get_algo_dlen(GCRY_MD_SHA512), output_file) ;

    // Print HMAC for testing
/*    printf("HMAC: ");
    for(i = 0; i < 64; i++)putchar(*(md_string+i)) ;
    printf("\n");
*/
}

void init_gcrypt_lib()
{
    // Check for Version mismatch
    if (!gcry_check_version (GCRYPT_VERSION)) printf("libgcrypt version mismatch\n") ;
    // Turn off Warnings
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control (GCRYCTL_DISABLE_SECMEM) ;

    // Create AES256 handle
    gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0) ;

    // Create HMAC handle
    gcry_md_open(&hmac_handle, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC) ;
    strcpy(hmac_key, "one test SHA key") ;
    gcry_md_setkey(hmac_handle, hmac_key, strlen(hmac_key)) ;

    // Set Initialization Vector
    strcpy(IV, "one test AES key") ;
    gcry_cipher_setiv(handle, IV, 16) ;
    gcry_create_nonce(IV, 16) ;
    // Create key from password
    strcpy(salt, "one test AES keyone test AES key") ;
    gcry_kdf_derive(password, strlen(password) , GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, 32, 4096, 32, password_key) ;
    gcry_cipher_setkey(handle, password_key, 32) ;

    // Turn on warnings
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    return ;
}







int main(int argc, char* argv[])
{
    // Check for illegal arguments
	if(argc < 2)
	{
		printf("\n\nArgument format:\n\n");
		printf("ncsuenc <input file> [<output IP-addr:port>]\n\n");
		return 0;
	}
	else if (argc > 3)
	{
		printf("\n\nToo many arguments!\n\n");
        printf("\n\nArgument format:\n\n");
		printf("ncsuenc <input file> [<output IP-addr:port>]\n\n");
		return 0;
	}


    // Process arguments
	else
		{
		// Prompt user for password
		printf("Please specify a password for file encryption:\n") ;
		scanf("%s", password) ;

        // Create input, output file names
		strcpy(input_file_name, argv[1]) ;
        strcpy(output_file_name, input_file_name) ;
        strcat(output_file_name, ".ncsu") ;

        // Initialize gcrypt library
		init_gcrypt_lib() ;

        // Option- Store encrypted data
        if (argc == 2)
            {
            // Open input and output files
            input_file = fopen(input_file_name, "rb") ;
            output_file = fopen(output_file_name, "wb") ;

            // Begin storing encrypted data
            store_encrypted() ;

            // Close input and output files
            fclose(output_file) ;
            fclose(input_file) ;

            // Close gcrypt handles
            gcry_md_close(hmac_handle);
            gcry_cipher_close(handle) ;

            }

        // Option- Transmit encrypted data
        else if( argc == 3)
            {

            // Open input file
            input_file = fopen(input_file_name, "rb") ;

            // Find the ":"	in second argument and parse accordingly
            strcpy(second_arg, argv[2]) ;
            strcpy(port_string, strchr(second_arg, ':')+1) ;
            port_int = atoi(port_string) ;
            *strchr(second_arg, ':') = '\0' ;
            strcpy(ip_address, second_arg) ;

            // Begin transmitting encrypted data
            transmit_encrypted() ;

            // Close input file
            fclose(input_file) ;

            // Close gcrypt handles
            gcry_md_close(hmac_handle) ;
            gcry_cipher_close(handle) ;

            }
		}

	return 0;
}


