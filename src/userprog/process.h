#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

// file descriptor struct
// keeps a mapping between file 
// descriptor num and file stream struct
struct fd {
  struct list_elem elem;
  int fd_num;
  struct file *file;
};

struct file* get_file(int fd, bool delete);
tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

#endif /* userprog/process.h */
