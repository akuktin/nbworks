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

#endif /* NBWORKS_CONSTDEF_H */
