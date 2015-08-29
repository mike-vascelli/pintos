#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "filesys/inode.h"

static void syscall_handler(struct intr_frame *);
int lookup(int sys_num);
bool check_arguments(uint32_t *args, size_t argc);

void sys_null(uint32_t *args, struct intr_frame *);
void sys_exit(uint32_t *args, struct intr_frame *);
void sys_write(uint32_t *args, struct intr_frame *);
void sys_wait(uint32_t *args, struct intr_frame *);
void sys_halt(uint32_t *args, struct intr_frame *);
void sys_exec(uint32_t *args, struct intr_frame *);
void sys_create(uint32_t *args, struct intr_frame *);
void sys_remove(uint32_t *args, struct intr_frame *);
void sys_open(uint32_t *args, struct intr_frame *);
void sys_filesize(uint32_t *args, struct intr_frame *);
void sys_read(uint32_t *args, struct intr_frame *);
void sys_seek(uint32_t *args, struct intr_frame *);
void sys_tell(uint32_t *args, struct intr_frame *);
void sys_close(uint32_t *args, struct intr_frame *);

typedef void syscall_func(uint32_t *args, struct intr_frame *);

typedef struct syscall {
    syscall_func* func;
    int sys_num;
} syscall_t;

syscall_t syscall_table[] = {
    {sys_halt, SYS_HALT},
    {sys_exit, SYS_EXIT},
    {sys_exec, SYS_EXEC},
    {sys_wait, SYS_WAIT},
    {sys_create, SYS_CREATE},
    {sys_remove, SYS_REMOVE},
    {sys_open, SYS_OPEN},
    {sys_filesize, SYS_FILESIZE},
    {sys_read, SYS_READ},
    {sys_write, SYS_WRITE},
    {sys_seek, SYS_SEEK},
    {sys_tell, SYS_TELL},
    {sys_close, SYS_CLOSE},
    {sys_null, SYS_NULL},
};

#define ERRORCODE -1

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

int lookup(int sys_num) {
    int sys_index;
    for (sys_index = 0; sys_index < (int) (sizeof (syscall_table) / sizeof (syscall_t)); sys_index++) {
        if (sys_num == syscall_table[sys_index].sys_num) {
            return sys_index;
        }
    }
    return ERRORCODE;
}

static void
syscall_handler(struct intr_frame *f) {
    struct thread *t = thread_current();
    if (check_arguments(f->esp, 1) && *((uint32_t *) f->esp)) {
        uint32_t* args = ((uint32_t*) f->esp);
        int syscall_index = lookup(args[0]);
        if (syscall_index >= 0) {
            syscall_table[syscall_index].func(args + 1, f);
        }
    } else {
        t->wait_status->exit_code = ERRORCODE;
        thread_exit();
    }
}

void sys_null(uint32_t *args, struct intr_frame *f) {
    struct thread *t = thread_current();
    if (check_arguments(args, 1)) {
        f->eax = args[0] + 1;
    } else {
        t->wait_status->exit_code = ERRORCODE;
        thread_exit();
    }
}

void sys_exit(uint32_t *args, struct intr_frame *f UNUSED) {
    struct thread *t = thread_current();
    if (check_arguments(args, 1)) {
        if (t->wait_status) {
            t->wait_status->exit_code = args[0];
        }
        thread_exit();
    } else {
        t->wait_status->exit_code = ERRORCODE;
        thread_exit();
    }
}

// Gets and returns a file stream given a particular file descriptor.
// It DELETE is true, then it removes and deletes a matching file 
// descriptor node from the list of open files of the current process.
// Returns NULL if no mapping exists for the given file descriptor.

struct file*
get_file(int fd, bool delete) {
    struct thread *t = thread_current();
    struct list_elem *e;
    struct fd *stored_fd;
    for (e = list_begin(&t->file_descriptors); e != list_end(&t->file_descriptors);) {
        stored_fd = list_entry(e, struct fd, elem);
        if (stored_fd->fd_num == fd) {
            struct file *f = stored_fd->file;
            if (delete) {
                e = list_remove(&stored_fd->elem);
                free(stored_fd);
            }
            return f;
        }
        e = list_next(e);
    }
    return NULL;
}

void sys_write(uint32_t *args, struct intr_frame *f) {
    struct thread *t = thread_current();
    lock_acquire(&t->filesys_lock);
    struct file *file;
    if (check_arguments(args, 3) && args[1]
        && is_user_vaddr((const void *) args[1])
        && pagedir_get_page(t->pagedir, (const void *) args[1])) {
        if (STDOUT_FILENO == args[0]) {
            printf("%s", (char *) args[1]);
            f->eax = args[2];
        } else if ((file = get_file(args[0], false))) {
            f->eax = file_write(file, (const void *) args[1], args[2]);
        } else {
            f->eax = ERRORCODE;
        }
    } else {
        t->wait_status->exit_code = ERRORCODE;
        lock_release(&t->filesys_lock);
        thread_exit();
    }
    lock_release(&t->filesys_lock);
}

void sys_wait(uint32_t *args, struct intr_frame *f) {
    struct thread *t = thread_current();
    if (check_arguments(args, 1)) {
        f->eax = process_wait(args[0]);
    } else {
        t->wait_status->exit_code = ERRORCODE;
        thread_exit();
    }
}

void sys_halt(uint32_t *args UNUSED, struct intr_frame *f UNUSED) {
    shutdown_power_off();
}

void sys_exec(uint32_t *args, struct intr_frame *f) {
    struct thread *t = thread_current();
    if (check_arguments(args, 1) && args[0]) {
        f->eax = process_execute((const char *) args[0]);
    } else {
        t->wait_status->exit_code = ERRORCODE;
        thread_exit();
    }
}

void sys_create(uint32_t *args, struct intr_frame *f) {
    struct thread *t = thread_current();
    lock_acquire(&t->filesys_lock);
    if (check_arguments(args, 2) && args[0]) {
        f->eax = filesys_create((const char *) args[0], args[1]);
    } else {
        t->wait_status->exit_code = ERRORCODE;
        lock_release(&t->filesys_lock);
        thread_exit();
    }
    lock_release(&t->filesys_lock);
}

void sys_remove(uint32_t *args, struct intr_frame *f) {
    struct thread *t = thread_current();
    lock_acquire(&t->filesys_lock);
    if (check_arguments(args, 1) && args[0]) {
    } else {
        t->wait_status->exit_code = ERRORCODE;
        lock_release(&t->filesys_lock);
        thread_exit();
    }
    lock_release(&t->filesys_lock);
}

void sys_open(uint32_t *args, struct intr_frame *f) {
    struct thread *t = thread_current();
    lock_acquire(&t->filesys_lock);
    if (check_arguments(args, 1) && args[0]) {
        struct file* file;
        if ((file = filesys_open((const char *) args[0]))) {
            struct fd *new_descriptor;
            if ((new_descriptor = malloc(sizeof (struct fd)))) {
                new_descriptor->file = file;
                if (inode_get_open_cnt(file_get_inode(file)) > 1) {
                    file_deny_write(file);
                }
                f->eax = new_descriptor->fd_num = t->fd_count++;
                list_push_front(&t->file_descriptors, &new_descriptor->elem);
            } else {
                f->eax = ERRORCODE; // Out of memory
            }
        } else {
            f->eax = ERRORCODE;
        }
    } else {
        t->wait_status->exit_code = ERRORCODE;
        lock_release(&t->filesys_lock);
        thread_exit();
    }
    lock_release(&t->filesys_lock);
}

void sys_filesize(uint32_t *args, struct intr_frame * f) {
    struct thread *t = thread_current();
    lock_acquire(&t->filesys_lock);
    if (check_arguments(args, 1)) {
        struct file *file;
        if ((file = get_file(args[0], false))) {
            f->eax = file_length(file);
        } else {
            f->eax = ERRORCODE;
        }
    } else {
        t->wait_status->exit_code = ERRORCODE;
        lock_release(&t->filesys_lock);
        thread_exit();
    }
    lock_release(&t->filesys_lock);
}

void sys_read(uint32_t *args, struct intr_frame * f) {
    struct thread *t = thread_current();
    lock_acquire(&t->filesys_lock);
    if (check_arguments(args, 3) && args[1]
        && is_user_vaddr((const void *) args[1])
        && pagedir_get_page(t->pagedir, (const void *) args[1])) {
        struct file *file;
        if (STDIN_FILENO == args[0]) {
            char *buff = args[1];
            size_t i;
            for (i = 0; i < args[2]; i++) {
                buff[i] = input_getc();
            }
            f->eax = i;
            buff[i] = '\0';
        } else if ((file = get_file(args[0], false))) {
            f->eax = file_read(file, (void *) args[1], args[2]);
        } else {
            f->eax = ERRORCODE;
        }
    } else {
        t->wait_status->exit_code = ERRORCODE;
        lock_release(&t->filesys_lock);
        thread_exit();
    }
    lock_release(&t->filesys_lock);
}

void sys_seek(uint32_t *args, struct intr_frame * f UNUSED) {
    struct thread *t = thread_current();
    lock_acquire(&t->filesys_lock);
    if (check_arguments(args, 2)) {
        struct file *file;
        if ((file = get_file(args[0], false))) {
            file_seek(file, args[1]);
        }
    } else {
        t->wait_status->exit_code = ERRORCODE;
        lock_release(&t->filesys_lock);
        thread_exit();
    }
    lock_release(&t->filesys_lock);
}

void sys_tell(uint32_t *args, struct intr_frame * f) {
    struct thread *t = thread_current();
    lock_acquire(&t->filesys_lock);
    if (check_arguments(args, 0)) {
        struct file *file;
        if ((file = get_file(args[0], false))) {
            f->eax = file_tell(file);
        } else {
            f->eax = ERRORCODE;
        }
    } else {
        t->wait_status->exit_code = ERRORCODE;
        lock_release(&t->filesys_lock);
        thread_exit();
    }
    lock_release(&t->filesys_lock);
}

void sys_close(uint32_t *args, struct intr_frame * f UNUSED) {
    struct thread *t = thread_current();
    lock_acquire(&t->filesys_lock);
    if (check_arguments(args, 1)) {
        t->fd_count--;
        struct file *file;
        if ((file = get_file(args[0], true))) {
            file_close(file); // file_allow_write is automatically called
        } else {
            t->wait_status->exit_code = ERRORCODE;
            lock_release(&t->filesys_lock);
            thread_exit();
        }
    } else {
        t->wait_status->exit_code = ERRORCODE;
        lock_release(&t->filesys_lock);
        thread_exit();
    }
    lock_release(&t->filesys_lock);
}

// Checks user arguments

bool
check_arguments(uint32_t *args, size_t argc) {
    struct thread *t = thread_current();
    bool result;
    size_t i;
    for (i = 0; i < argc; i++) {
        result = (args + i) && is_user_vaddr((const void *) (args + i))
            && pagedir_get_page(t->pagedir, (const void *) (args + i));
        if (!result) {
            return false;
        }
    }
    return true;
}