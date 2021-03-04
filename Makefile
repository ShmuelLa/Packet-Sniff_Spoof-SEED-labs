CC = gcc
CFLAG = -Wall -Wextra -g -o

all: 
	$(CC) hw4ping.c $(CFLAG) ping.o
	$(CC) sniff.c $(CFLAG) sniff.o -lpcap
	$(CC) sniff2.c $(CFLAG) sniff2.o -lpcap
	$(CC) sniff3.c $(CFLAG) sniff3.o -lpcap
	

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