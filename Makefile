obj-m+=packet.o

all:
	make -C /lib/modules/4.14.88-1-lts/build/ M=$(PWD) modules
	$(CC) test.c -o test
clean:
	make -C /lib/modules/4.14.88-1-lts/build/ M=$(PWD) clean
	rm test
