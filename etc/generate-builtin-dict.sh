#!/bin/sh

echo "package ipfix"
echo "var builtinDictionary = Dictionary{"
curl -s http://www.ietf.org/rfc/rfc5102.txt | awk '
	BEGIN { fields = 0 }
	/^5\.[0-9]+\.[0-9]+/ { name=$2; fields++ }
	/ElementId:/ { id=$2; fields++ }
	/Abstract Data Type:/ { type=$4; fields++ }
	/^$/ {
		if (fields == 3) {
			print "dictionaryKey{0, " id "}: DictionaryEntry{Name: \"" name "\", Type: \"" type "\"},"
			fields=0
		}
	}
'
echo "}"
