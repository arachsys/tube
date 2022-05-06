BINDIR := $(PREFIX)/bin

CFLAGS := -march=native -O3 -Wall -Wfatal-errors

tube-server: server.c Makefile
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

install: tube-server
	mkdir -p $(DESTDIR)$(BINDIR)
	install -s $^ $(DESTDIR)$(BINDIR)

clean:
	rm -f tube-server *.o

.PHONY: clean install
