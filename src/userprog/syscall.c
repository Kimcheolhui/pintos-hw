#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include <string.h> // (hw3) 추가2
#include "lib/user/syscall.h" // (hw3) 추가2
#include "userprog/process.h" // (hw3) 추가
#include "devices/shutdown.h" // (hw3) 추가
#include "devices/input.h" // (hw3) 추가
#include "threads/vaddr.h" // (hw3) 추가
#include "userprog/pagedir.h" // (hw3) 추가
// #include "threads/synch.h"  // (hw3) 추가
#include "filesys/filesys.h"  // (hw3) 추가
#include "filesys/file.h" // (hw3) 추가
#include "filesys/off_t.h" // (hw3) 추가
// #include "devices/block.h"  // (hw3) 추가

// void syscall_exit (int status);
// void syscall_halt (void);

static int sys_write (int fd, const void *buffer, unsigned size);
static int sys_read (int fd, void *buf, unsigned size);
static void check_user (const void *uaddr);
static void syscall_handler (struct intr_frame *);
static int sys_wait(int pid);
static int sys_open (const char *file);
static int sys_filesize(int fd);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  
  int *sp = f->esp;
  check_user(sp);

  int syscall_num = *((int *) sp);

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
        check_user(sp + 1);
        f->eax = exec ((const char*) sp[1]); 
        break;
      }
    case SYS_WAIT: 
    {
      check_user(sp + 1);
      f->eax = sys_wait(sp[1]); 
      break;
    }
    case SYS_WRITE:
      {
        check_user(sp + 1);
        check_user(sp + 2);
        check_user(sp + 3);

        int fd = sp[1];
        const void *buf = (const void *) sp[2];
        unsigned size = (unsigned) sp[3];
        f->eax = sys_write (fd, buf, size);
        break;
      }
    case SYS_READ:
      {
        check_user(sp + 1);
        check_user(sp + 2);
        check_user(sp + 3);

        f->eax = sys_read (sp[1], (void*)sp[2], sp[3]);
        break;
      }
    case SYS_CREATE:
      {
        check_user(sp + 1);
        check_user(sp + 2);

	f->eax = sys_create((char *)sp[1], sp[2]);
        break;
      }
    case SYS_REMOVE:
      {
        check_user(sp + 1);

	f->eax = sys_remove((char *)sp[1]);
        break;
      }
    case SYS_OPEN:
      {
        check_user(sp + 1);

	f->eax = sys_open((char *)sp[1]);
        break;
      }
    case SYS_FILESIZE:
      {
        check_user(sp + 1);

	f->eax = sys_filesize((int)sp[1]);
        break;
      }
    case SYS_SEEK:
      {
        check_user(sp + 1);
        check_user(sp + 2);

	sys_seek((int)sp[1], (unsigned) sp[2]);
        break;
      }
    case SYS_TELL:
      {
        check_user(sp + 1);

	f->eax = sys_tell((int)sp[1]);
        break;
      }
    case SYS_CLOSE:
      {
        check_user(sp + 1);

	sys_close((int)sp[1]);
        break;
      }
    /*
    case SYS_MMAP:
      {

        break;
      }
    case SYS_MUNMAP:
      {

        break;
      }
    case SYS_CHDIR:
      {

        break;
      }
    case SYS_MKDIR:
      {

        break;
      }
    case SYS_READDIR:
      {

        break;
      }
    case SYS_INUMBER:
      {

        break;
      }
    */
    default:
      exit (-1);
  }
}

static int
add_file_to_table(struct file * st_f) {
  struct thread *t = thread_current();
  struct file **table = t->fd;
  int fd_idx = 3;

  while (table[fd_idx] && (fd_idx < 128)) {
    fd_idx++;
  }

  if (fd_idx >= 128)
    return -1;
  table[fd_idx] = st_f;
  return fd_idx;
}

static struct file *
find_file_from_table(int fd) {
  struct thread *t = thread_current();
  if (fd < 0 || fd >= 128)
    return NULL;
  return t->fd[fd];
}

static void
del_file_from_table(int fd) {
  struct thread *t = thread_current();
  if (fd < 0 || fd >= 128)
    return;
  t->fd[fd] = NULL;
}


void syscall_halt (void) {
  shutdown_power_off ();
}

void exit (int status) {
  int idx;
  struct thread *cur = thread_current ();
  cur->exit_status = status;

  // 열었던 파일 정리
  for (idx = 2; idx < 128; idx++) {
    sys_close(idx);
  }

  printf ("%s: exit(%d)\n", cur->name, status); // 종료 메시지 출력

  thread_exit ();
}

int exec (const char *cmd_line) {
  check_user(cmd_line);
  return process_execute (cmd_line);
}

static int
sys_wait (int pid) {
  return process_wait (pid);
}

static void 
check_user (const void *uaddr) {
  // if (!is_user_vaddr (uaddr) || pagedir_get_page (thread_current()->pagedir, uaddr) == NULL)
  if (uaddr == NULL || !is_user_vaddr (uaddr) || pagedir_get_page (thread_current()->pagedir, uaddr) == NULL) {
    exit (-1);
  }
}

static int
sys_write (int fd, const void *buffer, unsigned size)
{
  check_user (buffer); // 사용자 영역 주소인지 확인
 
  if ((off_t)size < 0) // off_t 기준 음수일 수 있음;
    return -1;
 
  // FD가 잘못되었거나, fd가 STDIN인 경우 X
  struct file * target_file = find_file_from_table(fd);
  if (fd == STDIN_FILENO || target_file == NULL)
    return -1;

  /* 콘솔 출력만 지원 (fd==1) */
  if (fd == 1)
  {
    putbuf (buffer, size);
    return (int) size;
  }

  return file_write(target_file, buffer, size);
}

static int 
sys_read (int fd, void *buf, unsigned size) {
  check_user (buf);
  if ((off_t) size < 0)
    return -1;

  int ret;
  unsigned i;
  struct file* target_file;

  // STDOUT은 미리 처리
  if (fd == STDOUT_FILENO)
    return -1;
  // FD가 소멸된 경우 제거
  target_file = find_file_from_table(fd);
  if (target_file == NULL)
    return -1;

  // STDIN이 Close인 경우는 위에서 해결됨.
  if (fd == STDIN_FILENO) {
    for (i = 0; i < size; i++) {
      ((uint8_t *)buf)[i] = input_getc ();
      if (((uint8_t *)buf)[i] == '\0')
        break;
    }
    return i;
  }

  // 일반 파일 읽기
  ret = file_read(target_file, buf, size);
  return ret;
}

static int
sys_open (const char *file) {
  struct file* new_file;
  int ret;

  check_user(file);

  // File 열기 시도
  new_file = filesys_open(file);
  if (new_file == NULL)
    return -1;

  // (hw3) ROX 대응: 자기 자신을 호출해서 연 경우, 쓰기를 차단한다.
  if (!strcmp(thread_name(), file))
    file_deny_write(new_file);

  // Process Open File Table 등록
  ret = add_file_to_table(new_file);
  if (ret == -1)
    file_close(new_file);
  return ret;
}

static int
sys_filesize(int fd) {
  struct file * target_file = find_file_from_table(fd);
  if (target_file == NULL)
    return -1;

  // STDIN, STDOUT의 크기를 정의할 수 있는가?
  if (fd == STDIN_FILENO || fd == STDIN_FILENO)
    return 0;

  return file_length(target_file);
}

static void
sys_seek(int fd, unsigned position) {
  struct file * target_file = find_file_from_table(fd);
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
    return;
  if (target_file == NULL)
    return;
  if ((off_t)position < 0)
    return;
  file_seek(target_file, position);
}

static unsigned
sys_tell (int fd) {
  struct file * target_file = find_file_from_table(fd);
  
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO || target_file == NULL)
    return -1;
  return file_tell(target_file);
}

static void 
sys_close (int fd) {
  struct file * target_file = find_file_from_table(fd);
  if (target_file == NULL) // 애초에 초기화 X
    return;
  // make check 결과, STDIN과 STDOUT에 대해 Close를 시도할 경우 요청을 거부해야 한다.
  // 정답이 exit(-1)이거나 모두 출력 후 exit(0)을 출력하는 방식으로 진행됨. 
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
    return;

  // dup가 없으니 Close하면 그냥 끊긴 걸로 간주한다.
  del_file_from_table(fd);
  if (fd != STDIN_FILENO && fd != STDOUT_FILENO) {
    file_close(target_file);
  }
}

static bool
sys_create (const char *file, unsigned initial_size) {
  check_user(file);
  if ((int)initial_size < 0)
    return false;
  return filesys_create(file, initial_size);
}

static bool
sys_remove (const char *file) {
  check_user(file);
  return filesys_remove(file);
}

