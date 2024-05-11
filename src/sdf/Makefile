
CC=gcc
CFLAGS=-fPIC -Wall
LDFLAGS=-shared
LIBS=-lgmssl -framework Security

TARGET=libsoft_sdf.so
OBJS=soft_sdf.o

all: $(TARGET)

$(OBJS): soft_sdf.c
	$(CC) $(CFLAGS) -c soft_sdf.c -o $@

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS) -Wl,-exported_symbols_list,soft_sdf.exp

clean:
	rm -f $(OBJS) $(TARGET)

install:
	cp $(TARGET) /usr/local/lib
	ldconfig

uninstall:
	rm /usr/local/lib/$(TARGET)
	ldconfig

