BINDIR := $(PREFIX)/bin
CHROOT := /run/empty
CHUSER := nobody
SERVER := tube.cdw.me.uk:3456

CFLAGS := -march=native -O3 -Wall -Wfatal-errors

tube-%:: %.c Makefile
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

all: tube-client tube-server

tube-client: override CFLAGS += -DSERVER=\"$(SERVER)\" -pthread
tube-client: duplex.h x25519.[ch]

tube-server: override CFLAGS += -DCHROOT=\"$(CHROOT)\"
tube-server: override CFLAGS += -DCHUSER=\"$(CHUSER)\"

install: tube-client tube-server
	mkdir -p $(DESTDIR)$(BINDIR)
	install -s $^ $(DESTDIR)$(BINDIR)
	install examples/* $(DESTDIR)$(BINDIR)

clean:
	rm -f tube-client tube-server

.PHONY: all clean install
