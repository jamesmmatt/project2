#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h" //virtual address
#include "list.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);
void* check_address(const void*);
struct proc_file* search_from_list(struct list* files, int fd);
extern bool is_running;

// added this
struct proc_file {
  struct list_elem elem;
  int fd;
  struct file* pointer;
};

void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f UNUSED) 
{
//  added this: and switch statement
  int * pointer = f->esp;
  check_address(pointer);
  int system_call = * pointer;

	switch (system_call)
	{
    /* Terminates pintos w/shutdown_power_off (from theads/init.h). Barely used, possible deadlock situations so could lose information */
		case SYS_HALT:
      shutdown_power_off();
    break;

    /*Terminates the current user program, returing status to the kernel. if the process's parent waits for it
      this is the status that will be returned. a status of 0 indicates success and nonzero values indicate erros */
		case SYS_EXIT:
      check_address(pointer + 1);
      exit_proc(*(pointer + 1));
    break;

    /* Runs the executable wose name is given in cmd_line, passing any given arguments, and returns the new program id */
    case SYS_EXEC:
      // hex_dump(*(pointer + 1),*(pointer + 1), 64, true); used for testing
      check_address(pointer + 1);
      check_address(*(pointer + 1));
      f->eax =exec_proc(*(pointer + 1));
    break;

    case SYS_WAIT:
      check_address(pointer + 1);
      f->eax = process_wait(*(pointer + 1));
    break;

    /* creates a new file (creating does not open the file) */
    case SYS_CREATE:
      check_address(pointer + 5);
      check_address(*(pointer + 4));
      acquire_filesystem_lock();
      f->eax = filesys_create(*(pointer + 4), *(pointer + 5));
      release_filesystem_lock();
    break;

    /* deletes a file */
    case SYS_REMOVE:
      check_address(pointer + 1);
      check_address(*(pointer + 1));
      acquire_filesystem_lock();
      if(filesys_remove(*(pointer + 1)) == NULL)
        f->eax = false;
      else
        f->eax = true;
      release_filesystem_lock();
    break;

    /* opens a file, non negative fd "file descriptor" if it could be open or "-1" if it couldnt */
    case SYS_OPEN:
      check_address(pointer + 1);
      check_address(*(pointer + 1));
      acquire_filesystem_lock();
      struct file* file_pointer = filesys_open(*(pointer + 1));
      release_filesystem_lock();
      if(file_pointer == NULL)
        f->eax = -1;
      else
        {
          struct proc_file *pfile = malloc(sizeof(*pfile));
          pfile->pointer = file_pointer;
          pfile->fd = thread_current()->fd_count;
          thread_current()->fd_count++;
          list_push_back(&thread_current()->files, &pfile->elem);
          f->eax = pfile->fd;
        }
    break;

    // this just gets the file size
    case SYS_FILESIZE:
      check_address(pointer + 1);
      acquire_filesystem_lock();
      f->eax = file_length(search_from_list(&thread_current()->files, *(pointer + 1))->pointer);
      release_filesystem_lock();
    break;

    /* reads the size bytes from the file open into buffer. Fd 0 reads from the keyboard using input_getc.
    will store the bytes actually read or -1 if it couldnt be read */
    case SYS_READ:
      check_address(pointer + 7);
      check_address(*(pointer + 6));
      if(*(pointer + 5) == 0)
      {
        int i;
        uint8_t* buffer = *(pointer + 6);
        for(i = 0; i < *(pointer + 7); i++)
        {
          buffer[i] = input_getc(); //reads from keybaord
        }
        f->eax = *(pointer + 7);
      }
      else
      {
        struct proc_file* file_pointer = search_from_list(&thread_current()->files, *(pointer + 5));
        if(file_pointer == NULL)
        {
          f->eax = -1;
        }
        else
        {
          acquire_filesystem_lock();
          f->eax = file_read(file_pointer->pointer, *(pointer + 6), *(pointer + 7));
          release_filesystem_lock();
        }
      }
    break;

    /*writes size bytes from buffer to the open file. Gets the number of bytes actually written.
      writing pas end-of-file would normally extend the file, but file growth is not implemented by
      the basic file system. The expected behavior is to write as many bytes as possible up to the end-of-file
      and get the actual number writte, or 0 if no bytes could be written at all
      writes all of the bufer in one call with putbuf(). */  
		case SYS_WRITE:
    check_address(pointer + 7);
    check_address(*(pointer + 6));
		if(*(pointer + 5) == 1)
		{
			putbuf(*(pointer + 6), *(pointer + 7));
      f->eax = *(pointer + 7);
		}
    else
		{
			struct proc_file* file_pointer = search_from_list(&thread_current()->files, *(pointer + 5));
			if(file_pointer == NULL)
				f->eax = -1;
			else
      {
        acquire_filesystem_lock();
				f->eax = file_write(file_pointer->pointer, *(pointer + 6), *(pointer + 7));
        release_filesystem_lock();
      }
		}
		break;

    case SYS_SEEK:
      check_address(pointer + 5);
      acquire_filesystem_lock();
      file_seek(search_from_list(&thread_current()->files, *(pointer + 4))->pointer, *(pointer + 5));
      release_filesystem_lock();
		break;

		case SYS_TELL:
      check_address(pointer + 1);
      acquire_filesystem_lock();
      f->eax = file_tell(search_from_list(&thread_current()->files, *(pointer + 1))->pointer);
      release_filesystem_lock();
		break;

    /*closes the file descriptor */
		case SYS_CLOSE:
      check_address(pointer + 1);
      acquire_filesystem_lock();
		  close_file(&thread_current()->files, *(pointer + 1));
      release_filesystem_lock();
    break;

		default:
    printf("%d\n", *pointer);
	}
}

// where we utilize vaddr
void* check_address(const void *vaddr)
{

	if (!is_user_vaddr( vaddr ))
	{
    exit_proc(-1);
		return 0;
	}

	void *pointer = pagedir_get_page(thread_current()->pagedir, vaddr);

	if (!pointer)
	{
    exit_proc(-1);
		return 0;
	}

	return pointer;
}

struct proc_file* search_from_list(struct list* files, int fd)
{

	struct list_elem *element;

  for (element = list_begin(files); element != list_end(files); element = list_next(element))
  {
    struct proc_file *file = list_entry(element, struct proc_file, elem);
    if(file->fd == fd)
      return file;
  }

  return NULL;
}

void close_file(struct list* files, int fd)
{

	struct list_elem *element;

  struct proc_file *file;

  for (element = list_begin(files); element != list_end(files); element = list_next(element))
  {
    file = list_entry (element, struct proc_file, elem);
    if(file->fd == fd)
    {
      file_close(file->pointer);
      list_remove(element);
    }
  }
}

void close_all_files(struct list* files)
{

	struct list_elem *element;

  while(!list_empty(files))
  {
    element = list_pop_front(files);

    struct proc_file *file = list_entry(element, struct proc_file, elem);
    file_close(file->pointer);
    list_remove(element);
    free(file);
  }
} 

int exec_proc(char *file_name)
{
	acquire_filesystem_lock();
	char * file_name_copy = malloc(strlen(file_name) + 1);
  strlcpy(file_name_copy, file_name, strlen(file_name) + 1);

  char * save_ptr;
  file_name_copy = strtok_r(file_name_copy," ",&save_ptr);

  struct file* file = filesys_open (file_name_copy);

  if(file == NULL)
  {
    release_filesystem_lock();
    return -1;
  }
  else
  {
    file_close(file);
    release_filesystem_lock();
    return process_execute(file_name);
  }
}

void exit_proc(int status)
{
	struct list_elem *element;

  for (element = list_begin (&thread_current()->parent_thread->child_proc); element != list_end (&thread_current()->parent_thread->child_proc); element = list_next (element))
    {
      struct child *f = list_entry (element, struct child, elem);
      if(f->tid == thread_current()->tid)
      {
        f->have_used = true;
        f->exit_error = status;
      }
    }

	thread_current()->exit_error = status;

	if(thread_current()->parent_thread->waitingon == thread_current()->tid)
		sema_up(&thread_current()->parent_thread->child_lock);

	thread_exit();
}