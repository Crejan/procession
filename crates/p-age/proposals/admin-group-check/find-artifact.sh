#!/bin/sh
# Prints the path of one build artifact from cargo's own JSON messages on standard input
# (`cargo ... --message-format=json`), so that nothing has to guess where this cargo put it.
#   sh find-artifact.sh test stage1_sudo   < messages     (a test target)
#   sh find-artifact.sh bin  pledge        < messages     (a binary)
# Needs only grep and sed. Exits 1, and says why on standard error, unless exactly one
# compiler-artifact message names that target and has an absolute `executable` of plain characters.
set -u
KIND="${1:?usage: sh find-artifact.sh test|bin NAME < cargo-json}"
NAME="${2:?usage: sh find-artifact.sh test|bin NAME < cargo-json}"
FOUND=$(grep -F '"reason":"compiler-artifact"' | grep -F "\"kind\":[\"$KIND\"]" | grep -F "\"name\":\"$NAME\"" \
  | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p')
COUNT=$(printf '%s\n' "$FOUND" | grep -c .)
if [ "$COUNT" != 1 ]; then
  echo "find-artifact: expected one executable for the $KIND $NAME, found $COUNT" >&2
  exit 1
fi
case "$FOUND" in
  /*) ;;
  *) echo "find-artifact: not an absolute path: $FOUND" >&2; exit 1 ;;
esac
case "$FOUND" in
  *\\*|*[!A-Za-z0-9_./+@%:,=-]*) echo "find-artifact: the path has characters this script does not take: $FOUND" >&2; exit 1 ;;
esac
printf '%s\n' "$FOUND"
