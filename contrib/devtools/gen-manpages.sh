#!/bin/sh

TOPDIR=${TOPDIR:-$(git rev-parse --show-toplevel)}
SRCDIR=${SRCDIR:-$TOPDIR/src}
MANDIR=${MANDIR:-$TOPDIR/doc/man}

SNOWGEMD=${SNOWGEMD:-$SRCDIR/snowgemd}
SNOWGEMCLI=${SNOWGEMCLI:-$SRCDIR/snowgem-cli}
SNOWGEMTX=${SNOWGEMTX:-$SRCDIR/snowgem-tx}

[ ! -x $SNOWGEMD ] && echo "$SNOWGEMD not found or not executable." && exit 1

# The autodetected version git tag can screw up manpage output a little bit
SNGVERSTR=$($SNOWGEMCLI --version | head -n1 | awk '{ print $NF }')
SNGVER=$(echo $SNGVERSTR | awk -F- '{ OFS="-"; NF--; print $0; }')
SNGCOMMIT=$(echo $SNGVERSTR | awk -F- '{ print $NF }')

# Create a footer file with copyright content.
# This gets autodetected fine for snowgemd if --version-string is not set,
# but has different outcomes for snowgem-cli.
echo "[COPYRIGHT]" > footer.h2m
$SNOWGEMD --version | sed -n '1!p' >> footer.h2m

for cmd in $SNOWGEMD $SNOWGEMCLI $SNOWGEMTX; do
  cmdname="${cmd##*/}"
  help2man -N --version-string=$SNGVER --include=footer.h2m -o ${MANDIR}/${cmdname}.1 ${cmd}
  sed -i "s/\\\-$SNGCOMMIT//g" ${MANDIR}/${cmdname}.1
done

rm -f footer.h2m
