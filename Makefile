BINDIR := $(PREFIX)/bin
SERVER := tube.cdw.me.uk:3456

CFLAGS := -march=native -O3 -Wall -Wfatal-errors

all: tube-client tube-server

tube-client: override CFLAGS += -DSERVER=\"$(SERVER)\"
tube-client: client.c duplex.h x25519.[ch] Makefile
	$(CC) $(CFLAGS) -pthread -o $@ $(filter %.c,$^)

tube-server: server.c Makefile
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

install: tube-client tube-server
	mkdir -p $(DESTDIR)$(BINDIR)
	install -s $^ $(DESTDIR)$(BINDIR)

clean:
	rm -f tube-client tube-server *.o

.PHONY: clean install
