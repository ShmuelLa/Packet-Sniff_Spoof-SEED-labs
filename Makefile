CC = gcc
CFLAG = -Wall -Wextra -g -o

all: 
	$(CC) sniff_spoof.c $(CFLAG) sniff.o -lpcap
	$(CC) hw4/myping.c $(CFLAG) hw4ping.o
	$(CC) hw4/sniff.c $(CFLAG) hw4sniff.o -lpcap

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