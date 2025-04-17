CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lelf

TARGET = squashelf
SRCS   = $(TARGET).c
OBJS   = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

