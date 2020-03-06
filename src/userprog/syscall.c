#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");

//  added this: and switch statement
  int * pointer = f->esp;

  int system_call = * pointer;
  // int sys_code = *(int*)f->esp; // gets the syscall code

	switch (system_call)
	{
		case SYS_WRITE: // write to a file
		printf("fd : %d | Length : %d\n",*(pointer + 5),*(pointer + 7));
		printf("buffer: %s\n",*(pointer+6));
		break;

		default:
		printf("No match\n");
	}

  thread_exit ();
}
