#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#define FALSE 0
#define TRUE  1

struct {
  unsigned long len;
  unsigned char pckt[100];
} dtg[] = {
{
  50, {
    0x12, 0x34, 0x01, 0x10,  0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x20, 0x46, 0x45, 0x45,
    0x42, 0x46, 0x43, 0x45,  0x48, 0x45, 0x46, 0x46,
    0x45, 0x45, 0x48, 0x46,  0x43, 0x46, 0x41, 0x43,
    0x41, 0x43, 0x41, 0x43,  0x41, 0x43, 0x41, 0x43,

    0x41, 0x43, 0x41, 0x41,  0x41, 0x00, 0x00, 0x20,
    0x00, 0x01
  }
}};

#include <nbworks.h>
typedef uint32_t ipv4_addr_t;
extern ipv4_addr_t nbworks__myip4addr;

int main() {
  struct sockaddr_in addr;
  int sckt, i, ret_val;

  nbworks_libinit();

  addr.sin_family = AF_INET;
  fill_16field(137, (unsigned char *)&(addr.sin_port));
  fill_32field(nbworks__myip4addr, (unsigned char *)&(addr.sin_addr.s_addr));
  ret_val = 0;

  sckt = socket(PF_INET, SOCK_DGRAM, 0);
  if (sckt < 0) {
    fprintf(stderr, "could not open socket\n");
    ret_val = 1;
    return ret_val;
  }

  if (connect(sckt, &addr, sizeof(struct sockaddr_in))) {
    fprintf(stderr, "could not connect() socket\n");
    close(sckt);
    ret_val = 1;
    return ret_val;
  }

  for (i=0; i<1; i++) {
    fprintf(stderr, "sending name%i...", i +1);
    if (dtg[i].len > send(sckt, dtg[i].pckt, dtg[i].len, 0)) {
      fprintf(stderr, "failed\n");
      ret_val = 1;
      break;
    } else {
      fprintf(stderr, "succedded\n");
    }
  }

  close(sckt);
  if (ret_val)
    fprintf(stderr, "problems\n");
  else
    fprintf(stderr, "done\n");

  return ret_val;
}
