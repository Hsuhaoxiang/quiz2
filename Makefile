CC = gcc
all :xs
xs.o: xs.c
	$(CC) -c -o $@ $<

xs: xs.o
	$(CC) -o xs $^

clean:
	-rm *.o xs 

