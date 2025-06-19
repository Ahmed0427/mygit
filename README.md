# mygit

Thought Git was overkill? Same.  
So I built mygit, a duct-tape Git clone in C.  
It stages, it commits, it mostly works.  
Use at your own risk.
  
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
export PATH="$PATH:/path/to/mygit" # Replace /path/to/mygit with your actual path
```

Then try it:

```bash
mygit init                                        Init repo  
mygit add <paths...>                              Add files/dirs to index  
mygit cat-file <sha1>                             Prints the content of the repo obj 
mygit ls-files [-s]                               List index files (-s = detailed)  
mygit status                                      Show index vs working tree  
mygit commit -m MESSAGE --author="NAME <EMAIL>"   Commit with message and author  
mygit help                                        Show this message  
```
