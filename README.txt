Nikhil G. Khatu

- Makefile
- NCSUdec.c
- NCSUenc.c
- trial_in.txt

make ncsuenc
make ncsudec
make clean

#note option arguments must not have a space in it
./ncsuenc trial_in.txt ###May rename the file here###
./ncsuenc trial_in.txt <ip address>  ####currently defaults to port 5000 only, not fully functional####
./ncsudec -d5000 #### Not fully functional, but a TCP listener port may be specified ###
./ncsudec -itrial_in.txt.ncsu

Overview of work:
- Setup two seperate Linux virtual machines
- Installed libgcrypt library. This took a lot of time to figure out and install since I never did this before.
- Have code-blocks/linked recognize the libgcrypt library
- Learn socket programming for C
- Learn the gcrypt library
- Coding/Debugging


NCSUenc.c is divided into three different functions:
- main() - parses arguments and then according initializes the library, transmits the encrypted data, or stores the encrypted data locally.
- transmit_encrypted() - transmits the encrypted data via sockets. also calculates the HMAC(currently not functional in NCSUdec)
- store_encrypted() - stores encrypted data locally with '.ncsu' appended. (also calculates the HMAC)
- init_gcrypt_lib()- initializes the gcrypt library variables and keys.

NCSUdec.c is
- main()- parses arguments and then according initializes the library, starts the daemon on specified port, or decrypts a local file.
- file_daemon() - awaits a remote TCP connection and then encrypted file.
- decrypt_files() - decrypts a locally specified file
- init_gcrypt_lib() - initializes the grcypt library variables and keys

The shell/ command prompt isn't fully functional. However the encryption/decrytion, i/o, socket send/receive is functioning.

The PBKDF2 passphrase to key function indicated by standards requires "salt". Currently for the encryption functions "IV" and "salt" are both static.

Total number of hours spent: 30 to 40 hours.

