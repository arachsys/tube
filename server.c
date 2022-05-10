#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

enum { buffer = 65536, clients = 500, listeners = 20, tickets = 99 };

static struct ring {
  size_t done, head, length, peer, ticket;
  uint8_t data[buffer];
} ring[clients];

static struct pollfd fd[clients + listeners];

static size_t ticket[tickets];

static uintmax_t load(const uint8_t *data, size_t length) {
  uintmax_t result = 0;
  for (size_t byte = 0; byte < length; byte++)
    result |= (uintmax_t) data[byte] << (byte << 3);
  return result;
}

static void store(uint8_t *data, size_t length, uintmax_t value) {
  for (size_t byte = 0; byte < length; byte++)
    data[byte] = value >> (byte << 3);
}

static void initialise(void) {
  for (size_t id = 0; id < clients; id++)
    ring[id] = (struct ring) { .ticket = -1, .peer = -1 };
  for (size_t id = 0; id < clients + listeners; id++)
    fd[id] = (struct pollfd) { .fd = -1 };
  for (size_t id = 0; id < tickets; id++)
    ticket[id] = -1;
}

static struct addrinfo *lookup(const char *address) {
  struct addrinfo hints = { .ai_socktype = SOCK_STREAM }, *results;
  char host[256], port[32];
  int status;

  if (sscanf(address, "[%255[^]]]:%31[^:]", host, port) != 2) {
    if (sscanf(address, "%255[^:]:%31[^:]", host, port) != 2) {
      if (sscanf(address, ":%31[^:]", port) != 1)
        errx(EXIT_FAILURE, "%s: Invalid address", address);
      snprintf(host, sizeof(host), "::");
    }
  }
  if ((status = getaddrinfo(host, port, &hints, &results)) != 0)
    errx(EXIT_FAILURE, "getaddrinfo: %s", gai_strerror(status));
  return results;
}

static void attach(const char *address) {
  struct addrinfo *info, *list = lookup(address);
  size_t id = clients;

  for (info = list; info != NULL; info = info->ai_next) {
    while(fd[id].fd >= 0)
      if (++id >= clients + listeners)
        errx(EXIT_FAILURE, "Too many listener addresses");

    fd[id].fd = socket(info->ai_family, info->ai_socktype, 0);
    if (fd[id].fd < 0)
      err(EXIT_FAILURE, "socket");

    setsockopt(fd[id].fd, SOL_SOCKET, SO_REUSEADDR, &(int) { 1 },
      sizeof(int));
    fcntl(fd[id].fd, F_SETFL, O_NONBLOCK);

    if (bind(fd[id].fd, info->ai_addr, info->ai_addrlen) < 0)
      err(EXIT_FAILURE, "bind");
    if (listen(fd[id].fd, SOMAXCONN) < 0)
      err(EXIT_FAILURE, "listen");

    fd[id].events = POLLIN;
  }
  freeaddrinfo(list);
}

static void keepalive(int client) {
#if defined(TCP_KEEPCNT) && defined(TCP_KEEPIDLE) && defined(TCP_KEEPINTVL)
  setsockopt(client, IPPROTO_TCP, TCP_KEEPCNT, &(int) { 8 }, sizeof(int));
  setsockopt(client, IPPROTO_TCP, TCP_KEEPIDLE, &(int) { 120 }, sizeof(int));
  setsockopt(client, IPPROTO_TCP, TCP_KEEPINTVL, &(int) { 15 }, sizeof(int));
#endif
  setsockopt(client, SOL_SOCKET, SO_KEEPALIVE, &(int) { 1 }, sizeof(int));
}

static void suspend(void) {
  for (size_t id = clients; id < clients + listeners; id++)
    fd[id].events = 0;
}

static void resume(void) {
  for (size_t id = clients; id < clients + listeners; id++)
    fd[id].events = POLLIN;
}

static void new(size_t listener) {
  for (size_t id = 0; id < clients; id++)
    if (fd[id].fd < 0) {
      fd[id].fd = accept(fd[listener].fd, NULL, NULL);
      if (fd[id].fd >= 0) {
        fd[id].events = POLLIN;
        keepalive(fd[id].fd);
      }
      return;
    }
  suspend();
}

static void drop(size_t id) {
  if (ring[id].peer < clients) {
    size_t peer = ring[id].peer;
    close(fd[peer].fd);
    ring[peer] = (struct ring) { .ticket = -1, .peer = -1 };
    fd[peer] = (struct pollfd) { .fd = -1 };
  } else if (ring[id].ticket < tickets) {
    ticket[ring[id].ticket] = -1;
  }
  close(fd[id].fd);
  ring[id] = (struct ring) { .ticket = -1, .peer = -1 };
  fd[id] = (struct pollfd) { .fd = -1 };
  resume();
}

static size_t acquire(size_t id) {
  struct ring *r = ring + id;
  if (r->ticket < tickets)
    return r->ticket;
  if (r->length < 4 || r->head != r->length)
    return -1;
  r->ticket = load(r->data, 4) - 1;
  r->length -= 4;

  if (r->ticket < tickets && ticket[r->ticket] < clients) {
    r->peer = ticket[r->ticket];
    ring[r->peer].peer = id;
    ticket[r->ticket] = -1;
    return r->ticket;
  }

  if (r->ticket >= tickets)
    for (r->ticket = 0; r->ticket < tickets; r->ticket++)
      if (ticket[r->ticket] >= clients) {
        store(r->data, 4, r->ticket + 1);
        if (write(fd[id].fd, r->data, 4) != 4)
          break;
        ticket[r->ticket] = id;
        return r->ticket;
      }

  r->ticket = -1;
  return r->ticket;
}

static void fill(size_t id) {
  struct ring *r = ring + id;
  ssize_t count = read(fd[id].fd, r->data + r->head,
    r->head < r->length ? buffer - r->length : buffer - r->head);

  if (count > 0) {
    r->head += count, r->length += count;
    r->head -= r->head < buffer ? 0 : buffer;
  } else {
    if (count < 0 && (errno == EAGAIN || errno == EINTR))
      return;
    r->done = 1;
  }
}

static void drain(size_t id) {
  struct ring *r = ring + id, *w = ring + r->peer;
  if (r->peer < clients && w->length > 0) {
    size_t tail = w->head - w->length + (w->head < w->length ? buffer : 0);
    ssize_t count = write(fd[id].fd, w->data + tail,
      w->length + tail < buffer ? w->length : buffer - tail);

    if (count > 0)
      w->length -= count;
    if (count < 0 && errno != EAGAIN && errno != EINTR)
      w->length = 0, w->done = 2;
  }
}

static void update(size_t id) {
  struct ring *r = ring + id, *w = ring + r->peer;
  struct pollfd *rfd = fd + id, *wfd = fd + r->peer;

  if (r->peer >= clients) {
    rfd->events = r->length < buffer ? POLLIN : 0;
    if (r->done || (r->length >= 4 && acquire(id) >= tickets))
      drop(id);
    return;
  }

  rfd->events = r->length < buffer && r->done == 0 ? POLLIN : 0;
  wfd->events = w->length < buffer && w->done == 0 ? POLLIN : 0;

  if (r->length > 0) {
    wfd->events |= POLLOUT;
  } else if (r->done == 1) {
    shutdown(wfd->fd, SHUT_WR);
    r->done = 2;
  }

  if (w->length > 0) {
    rfd->events |= POLLOUT;
  } else if (w->done == 1) {
    shutdown(rfd->fd, SHUT_WR);
    w->done = 2;
  }

  if (r->done > 1 && w->done > 1)
    drop(id);
}

void sandbox(void) {
#if defined(CHROOT) && defined(CHUSER)
  if (getuid() == 0) {
    struct passwd *pw = getpwnam(CHUSER);
    if (pw == NULL)
      errx(EXIT_FAILURE, "getpwnam %s: User does not exist", CHUSER);
    if (chdir(CHROOT) < 0 || chroot(".") < 0)
      err(EXIT_FAILURE, "chroot %s", CHROOT);
    if (setgid(pw->pw_gid) < 0)
      err(EXIT_FAILURE, "setgid %u", pw->pw_gid);
    if (setgroups(0, NULL) < 0)
      err(EXIT_FAILURE, "setgroups");
    if (setuid(pw->pw_uid) < 0)
      err(EXIT_FAILURE, "setuid %u", pw->pw_uid);
  }
#endif
}

int main(int argc, char **argv) {
  if (argc < 2) {
    dprintf(STDERR_FILENO, "Usage: %s HOST:PORT...\n", argv[0]);
    return 64;
  }

  initialise();
  signal(SIGPIPE, SIG_IGN);
  for (int address = 1; address < argc; address++)
    attach(argv[address]);
  sandbox();

  while (1) {
    if (poll(fd, clients + listeners, -1) < 0) {
      if (errno == EINTR)
        continue;
      err(EXIT_FAILURE, "poll");
    }

    for (size_t id = 0; id < clients; id++) {
      if (fd[id].revents & (POLLIN | POLLHUP))
        fill(id);
      if (fd[id].revents & (POLLOUT | POLLERR))
        drain(id);
      if (fd[id].revents)
        update(id);
    }

    for (size_t id = clients; id < clients + listeners; id++) {
      if (fd[id].revents & POLLIN)
        new(id);
    }
  }
}
