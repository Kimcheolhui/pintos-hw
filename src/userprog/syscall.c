#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "userprog/process.h" // (hw3) 추가
#include "devices/shutdown.h" // (hw3) 추가
#include "devices/input.h" // (hw3) 추가
#include "threads/vaddr.h" // (hw3) 추가
#include "userprog/pagedir.h" // (hw3) 추가

// void syscall_exit (int status);
// void syscall_halt (void);

static int syscall_write (int fd, const void *buffer, unsigned size);
static int sys_read (int fd, void *buf, unsigned size);
static void check_user (const void *uaddr);
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int *esp = f->esp;
  int syscall_num = *((int *) f->esp);
  printf("디버깅디버깅디버깅4444444: %d\n", syscall_num); // 디버깅용 출력

  switch (syscall_num) {
    case SYS_HALT:
      {
        syscall_halt ();
        break;
      }
    case SYS_EXIT:
      { 
        int status = *((int *) (f->esp + 4));
        printf("디버깅디버깅디버깅555555: %d\n", status); // 디버깅용 출력
        syscall_exit (status);
        break;
      }
    case SYS_EXEC: 
      {
        f->eax = process_execute ((const char*) esp[1]); 
        break;
      }
    case SYS_WAIT: 
    {
      f->eax = process_wait (esp[1]); 
      break;
    }
    case SYS_WRITE:
      {
        printf("디버깅디버깅디버깅666666:\n"); // 디버깅용 출력
        int fd = esp[1];
        const void *buf = (const void *) esp[2];
        unsigned size = (unsigned) esp[3];
        f->eax = syscall_write (fd, buf, size);
        break;
      }
    case SYS_READ:
      {
        f->eax = sys_read (esp[1], (void*)esp[2], esp[3]);
        break;
      }
    default:
      syscall_exit (-1);
      break;
  }

}

void syscall_exit (int status) {
  struct thread *cur = thread_current ();
  cur->exit_status = status;
  thread_exit ();
}

void syscall_halt (void) {
  shutdown_power_off ();
}


static void check_user (const void *uaddr) {
  if (!is_user_vaddr (uaddr) || pagedir_get_page (thread_current()->pagedir, uaddr) == NULL)
    syscall_exit (-1);
}


static int
syscall_write (int fd, const void *buffer, unsigned size)
{
  check_user (buffer); // 사용자 영역 주소인지 확인
  /* 콘솔 출력만 지원 (fd==1) */
  if (fd == 1)
    {
      putbuf (buffer, size);
      printf("디버깅디버깅디버깅777777: %d\n", size); // 디버깅용 출력
      return (int) size;
    }
  /* 아직 지원 안 하는 경우 */
  return -1;
}

static int 
sys_read (int fd, void *buf, unsigned size) {
  check_user (buf);
  if (fd == 0) {
    unsigned i;
    for (i = 0; i < size; i++) ((uint8_t *)buf)[i] = input_getc ();
    printf("디버깅디버깅디버깅8888888: %d\n", size); // 디버깅용 출력
    return size;
  }
  return -1;
}