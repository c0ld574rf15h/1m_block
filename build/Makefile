EXE = 1m_block
CC = g++
CCFLAGS = --std=c++11

$(EXE) : main.o
	$(CC) $(CCFLAGS) -L ../bin -o $(EXE) main.o -lblock -lglog -lnetfilter_queue

main.o : main.cpp
	$(CC) $(CCFLAGS) -o main.o -c -I../include main.cpp

clean:
	rm -f main.o $(EXE)