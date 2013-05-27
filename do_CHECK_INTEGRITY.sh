#!/bin/sh

echo > SIZES.forcheck
echo > MD5SUMS.forcheck
echo > SHA1SUMS.forcheck

for i in BUGS COPYING INSTALL Makefile Y2K38 doc/*[^~] include/*[^~] nbworks.conf.SAMPLE src/*[^~] test/*[^~] tools/*[^~]; do
  sha1sum $i >> SHA1SUMS.forcheck;
  md5sum $i >> MD5SUMS.forcheck;
  ls -l $i | sed 's/^[^[:space:]]\+[[:space:]]\+[^[:space:]]\+[[:space:]]\+[^[:space:]]\+[[:space:]]\+[^[:space:]]\+[[:space:]]\+\([^[:space:]]\+\)[[:space:]]\+[^[:space:]]\+[[:space:]]\+[^[:space:]]\+[[:space:]]\+[^[:space:]]\+[[:space:]]\+\([^[:space:]].*\)$/\1 \2/' >> SIZES.forcheck;
done

sed -i '/^$/d' {SIZES,MD5SUMS,SHA1SUMS}.forcheck

if cmp SIZES{,.forcheck} &&
   cmp MD5SUMS{,.forcheck} &&
   cmp SHA1SUMS{,.forcheck}; then
  echo All is well in the land of men!
else
  echo BLOOD AND MURDER! SOMETHING IS AMISS!
  exit 1
fi

# I can not believe that that day finally came. I am ACTUALLY using cat for
# that single thing it was meant to do.
cat SIZES.forcheck MD5SUMS.forcheck SHA1SUMS.forcheck > MASTER_CHECKSUMS

echo The master hashes, sire! Check them. '(SIZE fist, SHA1 second, MD5 third)'
ls -l MASTER_CHECKSUMS | sed 's/^[^[:space:]]\+[[:space:]]\+[^[:space:]]\+[[:space:]]\+[^[:space:]]\+[[:space:]]\+[^[:space:]]\+[[:space:]]\+\([^[:space:]]\+\)[[:space:]]\+[^[:space:]]\+[[:space:]]\+[^[:space:]]\+[[:space:]]\+[^[:space:]]\+[[:space:]]\+\([^[:space:]].*\)$/\1  \2/'
sha1sum MASTER_CHECKSUMS
md5sum MASTER_CHECKSUMS
