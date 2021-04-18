#!/bin/bash

for i in $(head -c 14 /dev/urandom | hexdump -e '1/1 "%d "') ; do
  # only allow numbers 0 to 25 (0 index representation of A to Z)
  let i=i%26
  # zeroes can not be in the output so increase it by 1
  let i=i+1
  echo -n "$i "
done
echo

# decrypt: decrypt = subtract
# ensure all values are positive by starting from 26
# for example: cipher char 4, key 22 = 4-22 = -18
# (26+4-22)%26

# encrypt: just modulo 26
# (26+5+2)%26 = 7
# but so does (5+2)%26 = 7

#echo $(( 1 % 27 ))

for ((i=32;i<127;i++)) do printf "\\$(printf %03o "$i")"; done;printf "\n"
exit

x=0
for a in {A..Z} ; do
  let x=x+1
  echo "$a = $x"
done

echo $x
