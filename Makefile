CC=g++
CFLAGS=-Wall -Werror
LIBS=-lcrypto
all: ans
ans: main.o decodeLHM.o
	$(CC) main.o decodeLHM.o -o ans $(LIBS)
main.o: main.cpp decodeLHM.h
	$(CC) -c main.cpp
decodeLHM.o: decodeLHM.cpp
	$(CC) -c decodeLHM.cpp
clean:
	rm -rf *.o ans videoout2.mp4 videoout.mp4