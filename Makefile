ncsuenc: NCSUenc.c
	gcc -o ncsuenc NCSUenc.c `libgcrypt-config --cflags --libs`

ncsudec: NCSUdec.c
	gcc -o ncsudec NCSUdec.c `libgcrypt-config --cflags --libs`

clean: 
	rm ncsuenc ncsudec

