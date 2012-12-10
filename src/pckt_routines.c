#include <stdint.h>

inline unsigned char *read_16field(unsigned char *content,
				   uint16_t *field) {
  int i;

  for (i = 1; i >= 0; i--) {
    *field = (*field | *content) << (8 * i);
    content++;
  }

  return content;
}
inline unsigned char *read_32field(unsigned char *content,
                                   uint32_t *field) {
  int i;

  for (i = 3; i >= 0; i--) {
    *field = (*field | *content) << (8 * i);
    content++;
  }

  return content;
}

inline unsigned char *read_64field(unsigned char *content,
                                   uint64_t *field) {
  int i;

  for (i = 7; i >= 0; i--) {
    *field = (*field | *content) << (8 * i);
    content++;
  }

  return content;
}

inline unsigned char *fill_16field(uint16_t content,
				   unsigned char *field) {
  int i;
  uint16_t flags;

  flags = 0xff00;

  for (i = 1; i >= 0; i--) {
    *field = (unsigned char)((content & flags) >> (8 * i));
    field++;
    flags = flags >> 8;
  }

  return field;
}

inline unsigned char *fill_32field(uint32_t content,
				   unsigned char *field) {
  int i;
  uint32_t flags;

  flags = 0xff000000;

  for (i = 3; i >= 0; i--) {
    *field = (unsigned char)((content & flags) >> (8 * i));
    field++;
    flags = flags >> 8;
  }

  return field;
}

inline unsigned char *fill_64field(uint64_t content,
				   unsigned char *field) {
  int i;
  uint64_t flags;

  flags = 0xff00000000000000;

  for (i = 7; i >= 0; i--) {
    *field = (unsigned char)((content & flags) >> (8 * i));
    field++;
    flags = flags >> 8;
  }

  return field;
}
