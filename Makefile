CC = gcc
CFLAG = -Wall -Wextra -g -o

all: 
	$(CC) myping.c $(CFLAG) ping.o
	$(CC) sniff.c $(CFLAG) sniff.o -lpcap

git:
	git add -A
	git commit -m "$m"
	git push

ping:
	$(CC) myping.c $(CFLAG) ping.o
	sudo ./ping.o

sniff:
	$(CC) sniff.c $(CFLAG) sniff.o -lpcap
	sudo ./sniff.o

clean:
	rm -f *.o 