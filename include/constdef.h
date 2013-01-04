#ifndef NBWORKS_CONSTDEF_H
# define NBWORKS_CONSTDEF_H 1

# ifdef NULL
#  undef NULL
# endif
# define NULL 0

# ifdef ONES
#  undef ONES
# endif
# define ONES (~0)

# ifdef ONESZERO
#  undef ONESZERO
# endif
# define ONESZERO (~1)

# ifdef ZEROONES
#  undef ZEROONES
# endif
# define ZEROONES (~(1 >> 1))

# ifdef TRUE
#  undef TRUE
# endif
# define TRUE 1

# ifdef FALSE
#  undef FALSE
# endif
# define FALSE 0

# define T_1MS    (1000000)       /*   1 ms */
# define T_10MS   (10 * 1000000)  /*  10 ms */
# define T_250MS  (250 * 1000000) /* 250 ms */
# define T_500MS  (500 * 1000000) /* 500 ms */

# define TP_1MS   (1)   /*   1 ms, for poll() */
# define TP_10MS  (10)  /*  10 ms, for poll() */
# define TP_250MS (250) /* 250 ms, for poll() */
# define TP_500MS (500) /* 500 ms, for poll() */

/* general */
# define BCAST_REQ_RETRY_TIMEOUT T_250MS
# define BCAST_REQ_RETRY_COUNT   3
# define UCAST_REQ_RETRY_TIMEOUT 5 /* seconds */
# define UCAST_REQ_RETRY_COUNT   3
# define MAX_DATAGRAM_LENGTH     576 /* bytes, that is, octets */

#endif /* NBWORKS_CONSTDEF_H */
