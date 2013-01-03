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

# define TP_1MS   (1)   /*   1 ms, for poll() */
# define TP_10MS  (10)  /*  10 ms, for poll() */
# define TP_250MS (250) /* 250 ms, for poll() */

#endif /* NBWORKS_CONSTDEF_H */
