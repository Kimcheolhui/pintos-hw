#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

void syscall_exit (int status); // (hw3) 
void syscall_halt (void); // (hw3) 

#endif /* userprog/syscall.h */
