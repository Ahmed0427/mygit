# mygit

Ever thought,  “Why use Git when you can write your own and regret it?”
I did. So I made **mygit** — a Git clone in C. Works fine... until it doesn’t.
  
## How to Run

You’ll need:

- Linux (of course)
    
- gcc, make
    
- `zlib.h`, `openssl/sha.h`
    

### Build it:

```bash
make
```

### Use it:

Add the repo directory to your `PATH` so your terminal can find this beautiful mess:

```bash
export PATH="$PATH:/path/to/mygit"
```

Then try it:

```bash
mygit init
mygit add something.txt
mygit ls-files -s
mygit status
mygit commit
```

_Note: Replace `/path/to/mygit` with wherever you dumped this thing._
