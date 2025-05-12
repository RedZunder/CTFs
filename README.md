# My picoCTF exercises

## [My picoCTF profile](https://play.picoctf.org/users/RedZunder)
- [Cryptography](#cryptography)
- [Reverse engineering](#reverse-engineering)

# Cryptography

<details open>
<summary>Hashcrack</summary>
  
When we use _netcat_ to get the server, we are given a hash. Checking its length, we see it's 32 characters, or 128 bits, typical of MD5. 

Using ```hashcat -m 0 -a 0 <hash> /usr/share/wordlists/rockyou.txt``` we crack the password pretty quick.
The next hash is 40 char long, or 160 bits. Trying first with SHA-1, ```hashcat -m 0 -a 100 <hash> /usr/share/wordlists/rockyou.txt``` we again obtain the password. 

One last time, the hash is of length 64, or 256 bits. Supposing it's SHA-256 and running the same command with ```-a 1400```, we obtain the flag.

# Reverse Engineering
<details open>
<summary>Flag Hunters</summary>
  
We use _netcat_ to communicate with the server and download the Python source code. Checking the code, we observe:

```
elif re.match(r"CROWD.*", line):
    crowd = input('Crowd: ')
    song_lines[lip] = 'Crowd: ' + crowd
```
Which allows the user to enter anything, including commands.
We can also find:

```
elif re.match(r"RETURN [0-9]+", line):
    lip = int(line.split()[1])
```
Which returns to the beginning of one of the paragraphs from 0 to 9. The flag is stored in paragraph 0, which is not shown.
We can then inject the code ```blablabla; RETURN 0``` in order to trigger the RETURN case, and thus obtain the flag in plaintext.


</details>
