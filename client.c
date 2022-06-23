#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "duplex.h"
#include "x25519.h"

enum { chunk = 65518, key = 4, check = 8 };

const char base32[32] = "0123456789abcdefghjkmnpqrstvwxyz";

static duplex_t kx, rx, tx;

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

static void randomise(void *data, size_t length) {
  int getentropy(void *data, size_t length);
  if (getentropy(data, length) < 0)
    err(EXIT_FAILURE, "getentropy");
}

static struct addrinfo *lookup(const char *address) {
  struct addrinfo hints = { .ai_socktype = SOCK_STREAM }, *results;
  char host[256], port[32];
  int status;

  if (sscanf(address, "[%255[^]]]:%31[^:]", host, port) != 2)
    if (sscanf(address, "%255[^:]:%31[^:]", host, port) != 2)
      errx(EXIT_FAILURE, "%s: Invalid address", address);

  if ((status = getaddrinfo(host, port, &hints, &results)) != 0)
    errx(EXIT_FAILURE, "getaddrinfo: %s", gai_strerror(status));
  return results;
}

static int dial(const char *address) {
  struct addrinfo *info, *list = lookup(address);

  for (info = list; info != NULL; info = info->ai_next) {
    int fd = socket(info->ai_family, info->ai_socktype, 0);
    if (fd >= 0) {
      if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
        err(EXIT_FAILURE, "fcntl");
      if (connect(fd, info->ai_addr, info->ai_addrlen) >= 0) {
        freeaddrinfo(list);
        return fd;
      }
      close(fd);
    }
  }
  freeaddrinfo(list);
  err(EXIT_FAILURE, "connect %s", address);
}

static void interact(char *reply, size_t size, const char *format, ...) {
  static int tty = -1;
  struct termios old, new;
  ssize_t length;
  va_list args;

  if (tty < 0 && (tty = open("/dev/tty", O_RDWR | O_CLOEXEC)) < 0)
    err(EXIT_FAILURE, "open /dev/tty");

  tcgetattr(tty, &old);
  memcpy(&new, &old, sizeof(struct termios));
  new.c_lflag = new.c_lflag | ECHO | ECHOE | ECHOKE | ICANON | ISIG;
  new.c_iflag = (new.c_iflag & ~INLCR & ~IGNCR) | ICRNL;
  new.c_oflag = (new.c_oflag & ~OCRNL) | ONLCR | OPOST;
  tcsetattr(tty, TCSAFLUSH, &new);

  va_start(args, format);
  vdprintf(tty, format, args);
  va_end(args);

  if (reply) {
    while ((length = read(tty, reply, size - 1)) < 0)
      if (errno != EAGAIN && errno != EINTR)
        err(EXIT_FAILURE, "read /dev/tty");
    length -= reply[length - 1] == '\n';
    reply[length] = 0;
  }
  tcsetattr(tty, TCSAFLUSH, &old);
}

static void get(int fd, uint8_t *data, size_t length) {
  while (length > 0) {
    ssize_t count = read(fd, data, length);
    if (count < 0 && errno != EAGAIN && errno != EINTR)
      err(EXIT_FAILURE, "read");
    if (count == 0)
      errx(EXIT_FAILURE, "Connection terminated");
    if (count > 0)
      data += count, length -= count;
  }
}

static void put(int fd, const uint8_t *data, size_t length) {
  while (length > 0) {
    ssize_t count = write(fd, data, length);
    if (count < 0 && errno != EAGAIN && errno != EINTR)
      err(EXIT_FAILURE, "write");
    if (count > 0)
      data += count, length -= count;
  }
}

static size_t ticket(int server, size_t id) {
  uint8_t token[4];
  store(token, 4, id);
  put(server, token, 4);
  if (id == 0) {
    get(server, token, 4);
    id = load(token, 4);
  }
  return id;
}

static int initiate(const char *rendezvous) {
  int server = dial(rendezvous);
  size_t id = ticket(server, 0);
  char code[key + 1];

  randomise(code, key);
  for (size_t i = 0; i < key; i++)
    code[i] = base32[code[i] & 31];
  code[key] = 0;

  interact(NULL, 0, "Code: %zu-%s\n", id, code);
  duplex_absorb(kx, code, key);
  duplex_pad(kx);
  return server;
}

static int respond(const char *rendezvous) {
  int server = dial(rendezvous);
  size_t id = 0, length = 0;
  char code[key + 32], *cursor;

  interact(code, sizeof(code), "Code: ");
  for (id = strtoul(code, &cursor, 10); *cursor != 0; cursor++)
    if (isalnum(*cursor))
      code[length++] = tolower(*cursor);
  if (id == 0 || length == 0)
    errx(EXIT_FAILURE, "Invalid code");

  duplex_absorb(kx, code, length);
  duplex_pad(kx);
  ticket(server, id);
  return server;
}

static void exchange(int server) {
  x25519_t peer, point, scalar, shared;
  uint8_t auth[duplex_rate];

  duplex_squeeze(kx, point, x25519_size);
  x25519_point(point, point);
  randomise(scalar, x25519_size);
  scalar[0] &= 0xf8;
  x25519(point, scalar, point);

  put(server, point, x25519_size);
  get(server, peer, x25519_size);
  x25519(shared, scalar, peer);
  duplex_absorb(kx, shared, x25519_size);

  memcpy(rx, kx, duplex_size);
  duplex_absorb(rx, peer, x25519_size);
  memcpy(tx, kx, duplex_size);
  duplex_absorb(tx, point, x25519_size);

  duplex_squeeze(tx, auth, duplex_rate);
  put(server, auth, duplex_rate);

  get(server, auth, duplex_rate);
  duplex_decrypt(rx, auth, duplex_rate);
  if (duplex_compare(auth, 0, duplex_rate))
    errx(EXIT_FAILURE, "Authentication failed");
}

static void verify(void) {
  char code[check + 1], reply[32];

  duplex_squeeze(kx, code, check);
  for (size_t i = 0; i < check; i++)
    code[i] = base32[code[i] & 31];
  code[check] = 0;

  interact(reply, sizeof(reply), "Verify: %s? ", code);
  for (size_t i = 0; reply[i] && tolower(reply[i]) != 'y'; i++)
    if (isgraph(reply[i]))
      exit(EXIT_FAILURE);
}

static void detach(void *(*start)(void *), void *arg) {
  pthread_t thread;
  if (pthread_create(&thread, NULL, start, arg) < 0)
    err(EXIT_FAILURE, "pthread_create");
  if (pthread_detach(thread) < 0)
    err(EXIT_FAILURE, "pthread_detach");
}

static void spawn(int *child, int *input, int *output, char **argv) {
  int fd[4];

  if (argv[0] == NULL)
    return;
  if (pipe(fd) < 0 || pipe(fd + 2) < 0)
    err(EXIT_FAILURE, "pipe");
  if ((*child = fork()) < 0)
    err(EXIT_FAILURE, "fork");

  if (*child == 0) {
    if (dup2(fd[0], STDIN_FILENO) < 0)
      err(EXIT_FAILURE, "dup2");
    if (dup2(fd[3], STDOUT_FILENO) < 0)
      err(EXIT_FAILURE, "dup2");
    for (int i = 0; i < 4; i++)
      close(fd[i]);
    execvp(argv[0], argv);
    err(EXIT_FAILURE, "exec");
  }

  *input = fd[2];
  *output = fd[1];
  close(fd[0]);
  close(fd[3]);
}

static void *reap(void *arg) {
  pid_t child = *((pid_t **) arg)[0];
  int *status = ((int **) arg)[1];
  int *events = ((int **) arg)[2];

  if (child != 0) {
    waitpid(child, status, 0);
    if (WIFEXITED(*status))
      *status = WEXITSTATUS(*status);
    else
      *status = EXIT_FAILURE;
    close(events[1]);
  }
  close(events[5]);
  return NULL;
}

static void *receive(void *arg) {
  int input = *((int **) arg)[0];
  int output = *((int **) arg)[1];
  int *events = ((int **) arg)[2];
  uint8_t buffer[chunk + duplex_rate + 2];
  size_t length;

  do {
    get(input, buffer, 2);
    if ((length = load(buffer, 2)) > chunk)
      errx(EXIT_FAILURE, "Invalid chunk size");
    get(input, buffer + 2, length + duplex_rate);
    duplex_decrypt(rx, buffer + 2, length);
    duplex_pad(rx);
    duplex_decrypt(rx, buffer + length + 2, duplex_rate);
    if (duplex_compare(buffer + length + 2, 0, duplex_rate))
      errx(EXIT_FAILURE, "Authentication failed");
    if (output >= 0)
      put(output, buffer + 2, length);
  } while (length != 0);

  if (output >= 0)
    close(output);
  close(events[1]);

  while (read(input, &(char) { 0 }, 1) < 0)
    if (errno != EAGAIN && errno != EINTR)
      break;
  close(events[3]);
  return NULL;
}

static void *transmit(void *arg) {
  int input = *((int **) arg)[0];
  int output = *((int **) arg)[1];
  int *events = ((int **) arg)[2];
  uint8_t buffer[chunk + duplex_rate + 2];
  ssize_t length = 0;

  do {
    if (input >= 0)
      length = read(input, buffer + 2, chunk);
    if (length < 0 && errno != EAGAIN && errno != EINTR)
      err(EXIT_FAILURE, "read");
    if (length < 0)
      continue;
    store(buffer, 2, length);
    duplex_encrypt(tx, buffer + 2, length);
    duplex_pad(tx);
    duplex_squeeze(tx, buffer + length + 2, duplex_rate);
    put(output, buffer, length + duplex_rate + 2);
  } while (length != 0);

  close(events[3]);
  return NULL;
}

int main(int argc, char **argv) {
  char *rendezvous = getenv("SERVER") ?: SERVER;
  int input = fcntl(STDIN_FILENO, F_GETFD) < 0 ? -1 : STDIN_FILENO;
  int output = fcntl(STDOUT_FILENO, F_GETFD) < 0 ? -1 : STDOUT_FILENO;
  int events[6], server, status = EXIT_SUCCESS;
  pid_t child = 0;

  signal(SIGPIPE, SIG_IGN);
  if (argc >= 2 && strcmp(argv[1], "initiate") == 0) {
    server = initiate(rendezvous);
  } else if (argc >= 2 && strcmp(argv[1], "respond") == 0) {
    server = respond(rendezvous);
  } else {
    dprintf(STDERR_FILENO,
      "Usage: %s (initiate|respond) [CMD]...\n", argv[0]);
    return 64;
  }
  exchange(server);
  verify();

  spawn(&child, &input, &output, argv + 2);

  for (int i = 0; i < 6; i += 2)
    if (pipe(events + i) < 0)
      err(EXIT_FAILURE, "pipe");

  detach(reap, (void *[]) { &child, &status, events });
  detach(receive, (void *[]) { &server, &output, events });
  detach(transmit, (void *[]) { &input, &server, events });

  for (int i = 0; i < 6; i += 2)
    while (read(events[i], &(char) { 0 }, 1) != 0);
  return status;
}
