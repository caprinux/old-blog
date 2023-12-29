---
title: Relocation Read-Only (RELRO)
date: 0007-01-01T00:00:06Z
draft: false
description: nil
toc: false
---

## RELRO

> Relocation Read-Only (or RELRO) is a security measure which makes some binary sections read-only.

This means that you are unable to write or execute functions in these 'binary sections'.

RELRO can be **Partial** or **Full**. We will focus more on **Full RELRO** for the entirety of this tutorial series.

#### Partial

> Partial RELRO is the default setting in GCC, and nearly all binaries you will see have at least partial RELRO.

From an attackers point-of-view, partial RELRO makes almost no difference, other than it forces the GOT to come before the BSS in memory.

#### Full

> Full RELRO makes the entire GOT read-only

This prevents us from being able to carry out _certain exploits_, which we will cover later on in this series.

<br><br>

---

<div style="text-align: right"> <a href="/pwn/stack/bof">Chapter 4: Stack Buffer Overflow</a> </div>
