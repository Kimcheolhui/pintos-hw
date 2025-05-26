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
// #include "threads/synch.h"  // (hw3) 추가
// #include "filesys/filesys.h"  // (hw3) 추가
// #include "filesys/file.h" // (hw3) 추가
// #include "filesys/off_t.h" // (hw3) 추가
// #include "devices/block.h"  // (hw3) 추가

// void syscall_exit (int status);
// void syscall_halt (void);

static int syscall_write (int fd, const void *buffer, unsigned size);
static int sys_read (int fd, void *buf, unsigned size);
static void check_user (const void *uaddr);
static void syscall_handler (struct intr_frame *);

static int exec (const char *cmd_line);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  printf("핸들러핸들ㄹ러\n");
  
  
  int *sp = f->esp;
  int syscall_num = *((int *) sp);

  printf("syscall_num: %d\n", syscall_num);

  switch (syscall_num) {
    case SYS_HALT:
      {
        syscall_halt ();
        break;
      }
    case SYS_EXIT:
      { 
        // int status = *((int *) (sp + 4));
        check_user (sp + 1); // 사용자 영역 주소인지 확인
        exit (sp[1]);
        break;
      }
    case SYS_EXEC: 
      {
        printf("나야나나야나");
        f->eax = exec ((const char*) sp[1]); 
        break;
      }
    case SYS_WAIT: 
    {
      f->eax = process_wait (sp[1]); 
      break;
    }
    case SYS_WRITE:
      {
        int fd = sp[1];
        const void *buf = (const void *) sp[2];
        unsigned size = (unsigned) sp[3];
        f->eax = syscall_write (fd, buf, size);
        break;
      }
    case SYS_READ:
      {
        f->eax = sys_read (sp[1], (void*)sp[2], sp[3]);
        break;
      }
    default:
      printf("설마 여기?");
      exit (-1);
      break;
  }

}

void exit (int status) {
  struct thread *cur = thread_current ();
  cur->exit_status = status;

  printf ("%s: exit(%d)\n", cur->name, status); // 종료 메시지 출력

  thread_exit ();
}

int exec (const char *cmd_line) {
  printf("난가? exec\n");
  return process_execute (cmd_line);
}


void syscall_halt (void) {
  shutdown_power_off ();
}


static void check_user (const void *uaddr) {
  // if (!is_user_vaddr (uaddr) || pagedir_get_page (thread_current()->pagedir, uaddr) == NULL)
  if (!is_user_vaddr (uaddr)) {
    exit (-1);
  }
}


static int
syscall_write (int fd, const void *buffer, unsigned size)
{
  printf("syscall_write: fd=%d, size=%u\n", fd, size);
  check_user (buffer); // 사용자 영역 주소인지 확인
  /* 콘솔 출력만 지원 (fd==1) */
  if (fd == 1) {
      printf("출력이 제대로 되나?\n");
      putbuf (buffer, size);
      return (int) size;
  } else {
      printf("지원하지 않는 파일 디스크립터: %d\n", fd);
  }
  /* 아직 지원 안 하는 경우 */
  return -1;
}

static int 
sys_read (int fd, void *buf, unsigned size) {
  printf("sys_read: fd=%d, size=%u\n", fd, size);
  check_user (buf);
  if (fd == 0) {
    unsigned i;
    for (i = 0; i < size; i++) ((uint8_t *)buf)[i] = input_getc ();

    return size;
  }
  return -1;
}