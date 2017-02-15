
OBJ = main.o rtp.o pcap.o
exe = pcap2h264
CC = g++ -g
CCOPT = -Wall

$(exe):$(OBJ)
	$(CC) $(CCOPT) -D_FILE_OFFSET_BITS=64 -DMACOS -o $(exe) $(OBJ) -lpthread 

clean:
	rm -f *.o $(exe)
