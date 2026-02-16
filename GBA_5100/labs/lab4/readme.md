# Lab4 – RHEL Shell Scripting Exercises

Write a program called twice that takes a single integer argument and doubles its value:
Example: 
```bash
    $ twice 15
    30
    $ twice 0
    0
```

- twice.sh implementation below
```bash
[ec2-user@ip-172-31-26-10 ~]$ touch twice.sh
[ec2-user@ip-172-31-26-10 ~]$ vi twice.sh
[ec2-user@ip-172-31-26-10 ~]$ cat twice.sh
#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: twice <integer>"
    exit 1
fi

echo $(( $1 * 2 ))
[ec2-user@ip-172-31-26-10 ~]$ chmod +x twice.sh
[ec2-user@ip-172-31-26-10 ~]$ ./twice.sh 15
30
[ec2-user@ip-172-31-26-10 ~]$ ./twice.sh 0
0
[ec2-user@ip-172-31-26-10 ~]$
```

Write a program named home that accepts a username (from /etc/passwd) as its only argument and outputs the user’s home directory. Specifically:
/home/username

```bash
[ec2-user@ip-172-31-26-10 ~]$ touch home.sh
[ec2-user@ip-172-31-26-10 ~]$ vi home.sh
[ec2-user@ip-172-31-26-10 ~]$ cat home.sh
#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: home <username>"
    exit 1
fi

grep "^$1:" /etc/passwd | cut -d: -f6
[ec2-user@ip-172-31-26-10 ~]$ chmod +x home.sh
[ec2-user@ip-172-31-26-10 ~]$ ./home.sh
Usage: home <username>
[ec2-user@ip-172-31-26-10 ~]$ whoami
ec2-user
[ec2-user@ip-172-31-26-10 ~]$ ./home.sh ec2-user
/home/ec2-user
[ec2-user@ip-172-31-26-10 ~]$
```

Write a program called valid that prints yes if its argument is a legal shell variable name and no otherwise:4
example: 
```bash
    $ valid foo_bar
    yes
    $ valid 123
    no
```

Implementation below: 
```bash
[ec2-user@ip-172-31-26-10 ~]$ touch valid.sh
[ec2-user@ip-172-31-26-10 ~]$ vi valid.sh
[ec2-user@ip-172-31-26-10 ~]$ cat valid.sh
#!/bin/bash

if [[ $1 =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
    echo "yes"
else
    echo "no"
fi
[ec2-user@ip-172-31-26-10 ~]$ chmod +x valid.sh
[ec2-user@ip-172-31-26-10 ~]$ ./valid.sh foo_bar
yes
[ec2-user@ip-172-31-26-10 ~]$ ./valid.sh 123
no
[ec2-user@ip-172-31-26-10 ~]$
```

Write a program called thetime that displays the time of day in am or pm notation rather than in 24-hour clock time.

```bash
[ec2-user@ip-172-31-26-10 ~]$ touch thetime.sh
[ec2-user@ip-172-31-26-10 ~]$ vi thetime.sh
[ec2-user@ip-172-31-26-10 ~]$ cat thetime.sh
#!/bin/bash

hour=$(date +%H)
minute=$(date +%M)

if [ $hour -ge 12 ]; then
    suffix="pm"
else
    suffix="am"
fi

hour=$((hour % 12))

if [ $hour -eq 0 ]; then
    hour=12
fi

echo "$hour:$minute $suffix"
[ec2-user@ip-172-31-26-10 ~]$ chmod +x thetime.sh
[ec2-user@ip-172-31-26-10 ~]$ ./thetime.sh
11:59 pm
[ec2-user@ip-172-31-26-10 ~]$ ./thetime.sh
12:00 am
[ec2-user@ip-172-31-26-10 ~]$ date
Mon Feb 16 12:00:37 AM UTC 2026
[ec2-user@ip-172-31-26-10 ~]$
```