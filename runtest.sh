#! /bin/bash
if [[ $# != 1 ]]; then
    echo "usage: ./runtest.sh [TLD]"
fi

TLD="$1"

do_thing () {
    # NUM=$(($2 + 130))
    NUM=$2
    echo python test.py -x $TLD/$1/xinu.xbin -s $1 -t 45 galileo$NUM
    python test.py -x $TLD/$1/xinu.xbin -s $1 -t 45 galileo$NUM
}
export -f do_thing

for STUDENT in $(ls $TLD); do
    do_thing "${STUDENT}" "172"
    sleep 10
done
