```
grep -Ev '(^[^a-zA-Z0-9]|[^a-zA-Z0-9.-]|-{2,}|[^a-zA-Z0-9]$|.{64,}|\.{2,})' wordlist_brute.txt > filtered_wordlist.txt
```

Update resolvers:
```
axiom-exec "curl -fsS -o /tmp/r.txt https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt && test -s /tmp/r.txt && mv /tmp/r.txt /home/op/lists/resolvers.txt"
```

```
cat all_subdomain.txt | grep -P "(\.[\w-]+){3}$"
```

```
[
  {
    "command": "/home/op/go/bin/puredns resolve input --resolvers /home/op/lists/resolvers.txt -w output",
    "ext": "txt"
  }
]

```

naabu
```
ax exec 'naabu -up && dnsx -up && curl -fsS -o /tmp/r.txt https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt && test -s /tmp/r.txt && mv /tmp/r.txt /home/op/lists/resolvers.txt'
```
