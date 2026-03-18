#ifndef PQCLEAN_COMPAT_H
#define PQCLEAN_COMPAT_H

/* Prevent the compiler from optimising out conditionals using branches.
 * Used in constant-time code to avoid timing side-channels. */
#define PQCLEAN_PREVENT_BRANCH_HACK(v) __asm__("" : "+r"(v))

#endif /* PQCLEAN_COMPAT_H */
