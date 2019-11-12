CC = g++
CCFLAGS = --std=c++11
ARC = libblock.a
OBJS = utils.o

$(ARC) : $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

%.o : %.cpp
	$(CC) $(CCFLAGS) -o $@ -c -I../include/ $<

clean:
	rm -f *.o $(ARC)