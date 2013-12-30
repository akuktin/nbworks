#include <stdio.h>
#include <nbworks.h>

#define FALSE 0
#define TRUE  1
#define ONES (~0)

int main() {
  struct nbworks_nbnamelst *name_lst;
  unsigned long address;
  unsigned char target_label[] = "TARGETSES";

  nbworks_libinit();

  name_lst = alloca(sizeof(struct nbworks_nbnamelst) +
		    NBWORKS_NBNAME_LEN);
  nbworks_create_nbnamelabel(target_label, 0,
			     name_lst->name);
  name_lst->len = NBWORKS_NBNAME_LEN;
  name_lst->next_name = 0;

  address = nbworks_whatisIP4addrX(name_lst, ONES, FALSE, 0);

  if (address) {
    fprintf(stdout, "Adress of node: %s<00>: %i.%i.%i.%i\n", target_label,
	    ((address & 0xff000000) >> (8*3)),
	    ((address & 0x00ff0000) >> (8*2)),
	    ((address & 0x0000ff00) >> 8),
	    (address & 0x000000ff));
  } else {
    fprintf(stdout, "Could not find host: %s.\n", target_label);
  }

  return 0;
}
