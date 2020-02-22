
OBJ_DIR = ./obj
EXE_DIR = ./exe
H_DIR   = ./header
SRC_DIR = ./src

INCLUDES = -I./$(H_DIR)
SRCS = ethernet.c arp.c util.c 
OBJS = $(SRCS:.c=.o)
DEPS := $(H_DIR)/%.h

UTIL_O  = $(OBJ_DIR)/util.o
UTIL_H  = $(H_DIR)/util.h
UTIL_C  = $(SRC_DIR)/util.c

CC     = gcc
CFLAGS = -g -Wall

all: sniffer spoofer ping

libs: $(OBJ_DIR)/ethernet.o $(OBJ_DIR)/arp.o $(OBJ_DIR)/icmp.o $(UTIL_O)
	

sniffer: libs $(OBJ_DIR)/sniffer.o
	$(CC) $(CFLAGS) -o $(EXE_DIR)/sniffer.x $(UTIL_O) $(OBJ_DIR)/sniffer.o

spoofer: libs $(OBJ_DIR)/spoofer.o
	$(CC) $(CFLAGS) -pthread -o $(EXE_DIR)/spoofer.x $(UTIL_O) $(OBJ_DIR)/ethernet.o $(OBJ_DIR)/arp.o $(OBJ_DIR)/spoofer.o

ping: libs $(OBJ_DIR)/ping.o
	$(CC) $(CFLAGS) -o $(EXE_DIR)/ping.x $(UTIL_O) $(OBJ_DIR)/icmp.o $(OBJ_DIR)/ping.o

traceroute: libs $(OBJ_DIR)/traceroute.o
	$(CC) $(CFLAGS) -o $(EXE_DIR)/traceroute.x $(UTIL_O) $(OBJ_DIR)/icmp.o $(OBJ_DIR)/traceroute.o


$(OBJ_DIR)/ping.o: ping.c $(UTIL_H)
	$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/ping.o ping.c

$(OBJ_DIR)/sniffer.o: sniffer.c $(UTIL_H)
	$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/sniffer.o sniffer.c

$(OBJ_DIR)/spoofer.o: spoofer.c $(UTIL_H) $(H_DIR)/ethernet.h $(H_DIR)/arp.h
	$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/spoofer.o spoofer.c

$(OBJ_DIR)/traceroute.o: traceroute.c $(UTIL_H) $(H_DIR)/icmp.h
	$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/traceroute.o traceroute.c


$(OBJ_DIR)/ethernet.o : $(UTIL_H) $(SRC_DIR)/ethernet.c
	$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/ethernet.o $(SRC_DIR)/ethernet.c

$(OBJ_DIR)/arp.o : $(UTIL_H) $(SRC_DIR)/arp.c 
	$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/arp.o $(SRC_DIR)/arp.c
	
$(OBJ_DIR)/icmp.o : $(UTIL_H) $(SRC_DIR)/icmp.c 
	$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/icmp.o $(SRC_DIR)/icmp.c

$(UTIL_O): $(UTIL_C) $(UTIL_H)
	$(CC) $(CFLAGS) -c -o $(UTIL_O) $(UTIL_C)


.PHONY: clean

clean:
	rm $(OBJ_DIR)/* $(EXE_DIR)/*

