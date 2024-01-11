#include <sys/types.h>      // definitions of data types used in system calls
#include <sys/socket.h>     // definitions of structures needed for sockets
#include <netinet/in.h>     // constants and structures needed for internet domain addresses
#include <arpa/inet.h>      // definitions for internet operations
/*****************************/
#include <unistd.h>         // defines misc. symbollic constants and types. Declares misc. functions
#include <errno.h>          // defines macros to report error conditions through error codes in static location
/****************************/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <gcrypt.h>

void file_daemon(int) ;
void decrypt_file(char*, char*) ;
int main(int argc, char *argv[]) ;

void file_daemon(int port_int)
{
        int file_size ;
        int size_processed = 0 ;
        char ack[4] = "ACK\0" ;

        int sock, connected, bytes_received, true = 1 ;
        struct sockaddr_in server_addr, client_addr ;
        unsigned int sin_size ;
        FILE *out_file ;
        char out_file_name[50] = "\0" ;
        unsigned char data_buffer[16] ;
        unsigned char *md_string = NULL ;

        // Create Server Socket
		if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) perror("Socket");
    	if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&true,sizeof(int)) == -1) perror("Setsockopt");
		server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port_int);
    	server_addr.sin_addr.s_addr = INADDR_ANY;
		bzero(&(server_addr.sin_zero),8);
		if (bind(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) perror("Unable to bind");
		if (listen(sock, 5) == -1) perror("Listen");
		fflush(stdout);
        sin_size = sizeof(struct sockaddr_in);
        connected = accept(sock, (struct sockaddr *)&client_addr, &sin_size) ;

        // Get filename and open file
        bytes_received = recv(connected, out_file_name, 50, 0) ;
        if (bytes_received == -1) perror("Recv error\n");
        out_file = fopen(out_file_name, "wb") ;

        // Get File size from client and write to file
        bytes_received = recv(connected, &file_size, sizeof(int), 0) ;
        if (bytes_received == -1) perror("Recv error\n");
        fwrite(&file_size, 1, sizeof(int), out_file) ;

    	// Start receiving encrypted data from client
    	while(file_size > size_processed)
            {

            // Receive data from client, then send ack
            if((bytes_received = recv(connected, data_buffer, 16, 0)) == -1) perror("Recv error\n") ;
            send(connected, ack, 4, 0) ;

            // Write data to output file
            fwrite(data_buffer, 1, 16, out_file) ;

            // Increment
            size_processed += 16 ;
            }

        // Allocate memory for received HMAC
        md_string = malloc(gcry_md_get_algo_dlen(GCRY_MD_SHA512)) ;
        // Get HMAC from client
        if(recv(connected, md_string, 64, 0) == -1) perror("HMAC recv error\n") ;
        // Write HMAC to output file
        fwrite(md_string, 1, 64, out_file) ;

        // Print HMAC for testing
/*        printf("HMAC:");
        for(i = 0; i < 64; i++)putchar(*(md_string+i)) ;
        printf("\n");
*/
        // Close pending fd, socket, memory alloc
        close(connected) ;
        close(sock) ;
		fclose(out_file) ;
		free(md_string) ;

}





void decrypt_file(char* input_file_name, char* output_file_name)
{
    int file_size, flag, i ;
    int size_processed = 0;
    unsigned char *md_string = NULL ;
    unsigned char *md_string_file = NULL ;
    unsigned char data_buffer[16] ;

    gcry_cipher_hd_t handle ;
    gcry_md_hd_t hmac_handle ;
    gcry_error_t err = 0 ;
    FILE *input_file ;
    FILE *output_file ;

    char password[50] = "checkpass\0" ;
    char salt[32] ;
    char IV[16] ;
    char hmac_key[16] ;
    unsigned char password_key[32] ;

        // Open input/output files
		input_file = fopen(input_file_name, "rb") ;
        output_file = fopen(output_file_name, "wb") ;

		// Prompt user for password
		printf("Please specify a password for file decryption:\n") ;
        scanf("%s", password) ;


    // Check for Version mismatch
    if (!gcry_check_version (GCRYPT_VERSION)) printf("libgcrypt version mismatch\n") ;
    // Turn off warnings
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control (GCRYCTL_DISABLE_SECMEM) ;
    // Create AES256 handle
    gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0) ;
    // Create HMAC handle
    gcry_md_open(&hmac_handle, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC) ;
    strcpy(hmac_key, "one test SHA key") ;
    gcry_md_setkey(hmac_handle, hmac_key, strlen(hmac_key)) ;
    // Set Initialization vector
    strcpy(IV, "one test AES key") ;
    gcry_cipher_setiv(handle, IV, 16) ;
    // Set password key
    strcpy(salt, "one test AES keyone test AES key") ;
    gcry_kdf_derive(password, strlen(password) , GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, 32, 4096, 32, password_key) ;
    gcry_cipher_setkey(handle, password_key, 32) ;
    // Turn on Warnings
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Read file size from input file
    fread(&file_size, 1, sizeof(int), input_file);

    // Start decrypting from input file
    while(file_size > size_processed)
        {
        // Read encrypted from input file
        fread(data_buffer, 1, 16, input_file) ;

        // Decrypt data
        gcry_cipher_decrypt(handle, data_buffer, 16, NULL, 0) ;
        gcry_cipher_reset(handle) ;
        // Update HMAC
        gcry_md_write(hmac_handle, data_buffer, 16) ;
        gcry_md_reset(hmac_handle) ;


        if(file_size-size_processed >= 16) fwrite(data_buffer, 1, 16, output_file) ;
        else
            {
            fwrite(data_buffer, 1, (file_size- size_processed), output_file);
            size_processed += (file_size - size_processed) ;
            break ;
            }
        gcry_cipher_reset(handle) ;

        size_processed += 16;
        }


    // Read HMAC from file
    md_string_file = malloc(gcry_md_get_algo_dlen(GCRY_MD_SHA512)) ;
    fread(md_string_file, 1, gcry_md_get_algo_dlen(GCRY_MD_SHA512), input_file) ;
    // Get Calculated HMAC
    md_string = malloc(gcry_md_get_algo_dlen(GCRY_MD_SHA512)) ;
    for(i = 0; i < 64; i++) *(md_string + i) = *((gcry_md_read(hmac_handle, GCRY_MD_SHA512)) + i) ;


    // Compare calculated HMAC with HMAC from file
    flag = 0 ;
    for(i = 0; i < 64; i++) if( *(md_string + i) != *(md_string_file + i)) flag = 1;
    if(flag == 0) printf("Integrity Confirmed!\n") ;
    else printf ("Integrity Compromised!\n") ;

    // Print HMACs for testing
/*    printf("HMAC:");
    for(i = 0; i < 64; i++)putchar(*(md_string+i)) ;
    printf("\nHMAC_file:");
    for(i = 0; i < 64; i++)putchar(*(md_string_file+i)) ;
    printf("\n");
*/
    // Close fd, handles, memory alloc
    free(md_string) ;
    free(md_string_file) ;
    gcry_md_close(hmac_handle) ;
    gcry_cipher_close(handle) ;

    // Close input/output files
	fclose(output_file) ;
	fclose(input_file) ;
}




int main(int argc, char *argv[])
{
    char *tmp_ptr = "";
    char option[3] = "\0" ;
    char input_file_name[50] = "\0" ;
    char output_file_name[50] = "\0" ;

    // Check arguments for errors
	if (argc != 3)
		{
		printf("\n\nIncorrect # of arguments! Exiting! ") ;
		printf("Argument format:\n") ;
		printf("ncsudec [-d <port>] [-i <input file>]\n\n") ;
		exit(EXIT_FAILURE) ;
		}

    // Check argument formatting
	strcpy(option, argv[1]) ;
	if (option[0] != '-' || strlen(option) != 2)
		{
		printf("\n\nIncorrect first argument ") ;
		printf("Argument format:\n") ;
		printf("ncsudec [-d <port>] [-i <input file>]\n\n") ;
		exit(EXIT_FAILURE) ;
		}

	// Option: Incorrect
	if (option[1] != 'i' && option[1] != 'd')
		{
		printf("\n\nArgument option unavailable! ") ;
		printf("Argument format:\n") ;
		printf("ncsudec [-d <port>] [-i <input file>]\n\n") ;
		exit(EXIT_FAILURE) ;
		}

    // Option: decryption
	else if(option[1] == 'i')
		{
		// Derive Output filename
		strcpy(input_file_name, argv[2]) ;
		strcpy(output_file_name, input_file_name) ;
		tmp_ptr = strrchr(output_file_name, '.') ;
		*tmp_ptr = '\0' ;

		// Check output file name extension errors
		if (tmp_ptr == NULL)
			{
			printf("Incorrect input file extension!\n") ;
			exit(EXIT_FAILURE) ;
			}
		if (*(tmp_ptr + 1) != 'n')
			{
			printf("Incorrect input file extension!\n") ;
			exit(EXIT_FAILURE) ;
			}
		if (*(tmp_ptr + 2) != 'c')
			{
			printf("Incorrect input file extension!\n") ;
			exit(EXIT_FAILURE) ;
			}
		if (*(tmp_ptr + 3) != 's')
			{
			printf("Incorrect input file extension!\n") ;
			exit(EXIT_FAILURE) ;
			}
		if (*(tmp_ptr + 4) != 'u')
			{
			printf("Incorrect input file extension!\n") ;
			exit(EXIT_FAILURE) ;
			}

		// Start file decryption
		decrypt_file(input_file_name, output_file_name) ;
		}

    // Option: File Daemon
	else if(option[1] == 'd')
		{
        // Define port number from argument
		int port_int = atoi(argv[2]) ;

/*
        // Create file daemon process to run in background
        pid_t pid, sid;

        pid = fork();
        //printf("PID: %i\n", pid) ;
        if (pid < 0) exit(EXIT_FAILURE);
        if (pid > 0) exit(EXIT_SUCCESS);
        umask(0);
        sid = setsid();
        if (sid < 0) exit(EXIT_FAILURE);
        if (chdir("/") < 0) exit(EXIT_FAILURE);
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
*/
        // Enter infinite while loop to run daemon
        while(1)
            {
                file_daemon(port_int) ;
                //sleep(1) ;
            }
		}

	return 0;
}
