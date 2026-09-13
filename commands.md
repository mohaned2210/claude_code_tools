```
ax scp bug_hunter_crawler.py 'mhk*':/home/op/bug_hunter_crawler.py && \ ax exec 'python3 -m pip install --user requests beautifulsoup4 colorama urllib3 || python3 -m pip install --user --break-system-packages requests beautifulsoup4 colorama urllib3'
```
katana model:
```
[   {     "command": "/home/op/go/bin/katana -u _target_ -c 49 -p 50 -rl 100 -d 4 -silent -nc -kf all -jc -ef woff,css,svg,woff2,gif,svg -o output/_cleantarget_",     "ext": "txt",     "threads": "1"   } ]
```

Hakrawler model:
```
[   {     "command": "cat input | /home/op/go/bin/hakrawler -d 3 -insecure -u -t 50 -i -timeout 6600 -h \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\" | tee output",     "ext": "txt"   } ]
```
