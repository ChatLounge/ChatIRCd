#ifndef INCLUDED_operhash_h
#define INCLUDED_operhash_h

void init_operhash(void);
const char *operhash_add(const char *name);
const char *operhash_find(const char *name);
void operhash_delete(const char *name);

#endif
