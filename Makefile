CC = gcc
CFLAG = -Wall -Wextra -g -o

all: 
	$(CC) sniff_spoof.c $(CFLAG) sniff.o -lpcap

git:
	git add -A
	git commit -m "$m"
	git push

ping:
	$(CC) hw4ping.c $(CFLAG) ping.o
	sudo ./ping.o

sniff:
	$(CC) sniff.c $(CFLAG) sniff.o -lpcap
	sudo ./sniff.o

clean:
	rm -f *.o 