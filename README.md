locus
===================

Install pin (into `locus/pin-3.31`) & build locus

```
./install.sh
source ./source.sh
./build.sh
```

Run a program under Pin with the tool:
```
"$PIN_ROOT/pin" -t "$(pwd)/locus_pintool" -- /bin/ls -l
```

Run a program using a file to start/stop collecting data.
```
"$PIN_ROOT/pin" -follow_execv 1 -t ./locus_pintool -start_enabled 1 -- stress -m 1 --vm-bytes 2M -t 30

# In a different terminal:
echo start > outputs/ctl.fifo
echo stop > outputs/ctl.fifo
```