SRCS=$(wildcard *.c tinyalsa/*.c)
OBJS=$(patsubst %.c, %.o, $(SRCS))
HEADS=$(wildcard *.h)
CC=gcc
CFLAGS=-g -I./tinyalsa -I./tinyalsa/include
LDFLAGS=
TARGET=aiui_demo
$(TARGET):$(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%.o:%.c
	$(CC) -c $< -o $@ $(CFLAGS) 

clean:
	rm -rf $(OBJS) $(TARGET)
