## To make the JCShell able parse these scripts, perform the following steps

> Note: it's assumed that we're in the running docker environment

Run the JCShell application
```bash
root@user:workspace# /data/jcshell.sh 
``` 

Set the *path* variable which will point to the folder with scripts
```bash
- /set-var path /workspace/CryptoKey/Scripts/JCShell
```

Just pass over the name of a script you are about to run
```bash
- 01_install_test
```
