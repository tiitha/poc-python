#!/usr/bin/env python
import time

buffer_size = 8192		# read buffer size
line_break = "\n"		# custom event separator for multiline events 

f2bf = {				# files to be followed
	"/tmp/sitt_1.txt": 0,
	"/tmp/sitt_2.txt": 0
}

def follow():
	global buffer_size
	global line_break

	while 1:
		events = []
		for f in f2bf:
			pointer = f2bf[f]
			with open(f, "r") as fo:

# only tailing is needed. Comment out the following four lines
# to go through the whole file from beginning and continue tailing
				if pointer == 0:
					fo.seek(0,2)
					f2bf[f] = fo.tell()
				else:
					fo.seek(pointer)

				buf = fo.read(buffer_size)
				i = buf.rfind(line_break)
				if i == -1:
					continue;

				events += buf[:i].split(line_break)
				f2bf[f] += i + len(line_break)

		if events is not None and len(events) > 0:
			events = sorted(set(events))    # sort the events in order to preserve timeline
			for evt in events:
				print evt

		time.sleep(0.1)

follow()
