CC=clang
CFLAGS=-c -I. -Wall -pedantic
LDFLAGS=-s
SOURCES=Belt.c BeltHash.c main.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=belt_hash_test

all: $(EXECUTABLE)
    
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)
