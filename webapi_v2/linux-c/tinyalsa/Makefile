SRCS=$(wildcard *.c)
OBJS=$(patsubst %.c, %.o, $(SRCS))
HEADS=$(wildcard *.h)
CC=gcc
CFLAGS=-g -I./include
LDFLAGS=
TARGET=mytinyalsa
$(TARGET):$(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%.o:%.c
	$(CC) -c $< -o $@ $(CFLAGS) 

clean:
	rm -rf *.o $(TARGET)
