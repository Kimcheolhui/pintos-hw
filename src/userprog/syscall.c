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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  
  int *sp = f->esp;
  int syscall_num = *((int *) sp);

  printf ("여기 도달하기는 하나?: %d\n", syscall_num);

  switch (syscall_num) {
    case SYS_HALT:
      {
        syscall_halt ();
        break;
      }
    case SYS_EXIT:
      { 
        printf ("[DEBUG] EXIT하는 중 입니다\n: %d\n", sp[1]); // 디버깅용 출력
        // int status = *((int *) (sp + 4));
        check_user (sp + 1); // 사용자 영역 주소인지 확인
        exit (sp[1]);
        break;
      }
    case SYS_EXEC: 
      {
        printf ("[DEBUG] SYS_EXEC called with arg: %s\n", (const char*) sp[1]); // 디버깅용 출력
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
      printf ("[DEBUG] 알 수 없는 system call: %d\n", syscall_num);
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
  return process_execute (cmd_line);
}


void syscall_halt (void) {
  shutdown_power_off ();
}


static void check_user (const void *uaddr) {
  // if (!is_user_vaddr (uaddr) || pagedir_get_page (thread_current()->pagedir, uaddr) == NULL)
  if (!is_user_vaddr (uaddr))
    printf("정말 너니너ㅣ너니ㅓ니ㅓ니ㅓ니너니ㅓㄴ??????????\n");
    exit (-1);
}


static int
syscall_write (int fd, const void *buffer, unsigned size)
{
  check_user (buffer); // 사용자 영역 주소인지 확인
  /* 콘솔 출력만 지원 (fd==1) */
  if (fd == 1)
    {
      putbuf (buffer, size);
      // printf("디버깅디버깅디버깅777777: %d\n", size); // 디버깅용 출력
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
    // printf("디버깅디버깅디버깅8888888: %d\n", size); // 디버깅용 출력
    return size;
  }
  return -1;
}