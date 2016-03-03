#!/usr/bin/env python
import time, os, json, re

# define variables
root_path = "/logs" # root path for the log files
file_pattern = "[0-9]{8}.sitt_[0-9]{1}.log"     # log file pattern
buffer_size = 8192              # read buffer size
line_break = "\n"               # custom event separator for multiline events

sessions = {}                   # session database
f2bf = {                        # files to be followed
"/logs/app_1/20160303.sitt_1.log":0,
"/logs/app_1/20160303.sitt_2.log":0
}

# scans the defined root folder and sub-folders for files based on a predefined pattern
# sets the found files to be followed from the beginning

def scan_folder():
        global root_path
        # check for existing files in the queue
        tmp_f2bf = dict(f2bf)
        for f in tmp_f2bf:
                if not os.path.isfile(f):
                        # File-not-Found: remove file from queue
                        del f2bf[f]

        # searching for the new files in the root path
        for dirname, dirnames, filenames in os.walk(root_path):
                if len(filenames)>0:
                        for f in filenames:
                                ff = dirname+"/"+f
                                if fp.match(f) and ff not in f2bf:
                                        f2bf[ff] = 0

# follows the files defined in the queue
# refresh rate defined as 0.1 seconds for lower hunger for cpu

def follow():
        global buffer_size
        global line_break

        while 1:
                scan_folder()
                events = []
                for f in f2bf:
                        pointer = f2bf[f]
                        with open(f, "r") as fo:

# currently set up as tail -f (follow from the current pointer)
# if you want the new files to be analyzed from the beginning, comment out the following four lines

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

# if events are not to be sorted, exclude the list usage in processing

                if events is not None and len(events) > 0:
                        events = sorted(set(events))    # sort the events in order to preserve timeline
                        for evt in events:
                                parse_event( evt )

                time.sleep(0.1)

def parse_event(evt):
                print evt

# pre-compile the filename pattern
fp = re.compile(file_pattern)
follow()
