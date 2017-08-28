#!/usr/bin/env python
import time

buffer_size = 8192        # read buffer size
line_break = "\n"        # custom event separator for multiline events 
file_pattern = "/logs/data_[0-9]/*/*.access.log"

f2bf = {                # files to be followed
}


def scan_folder():
    # check for existing files in the queue
    tmp_f2bf = dict(f2bf)
    for f in tmp_f2bf:
        if not os.path.isfile(f):
            # File-not-Found: remove file from queue
            del f2bf[f]

    # searching for the new files in the root path
    for ff in glob.glob(file_pattern):
        if ff not in f2bf:
            f2bf[ff] = 0


def follow():
    while 1:
        scan_folder()
        events = []
        for f in f2bf:
            pointer = f2bf[f]
            try:
                with open(f, "r") as fo:
                    if pointer == 0:
                        fo.seek(0,2)
                        f2bf[f] = fo.tell()
                    else:
                        fo.seek(pointer)

                    buf = fo.read(buffer_size)
                    i = buf.rfind(line_break)
                    if i == -1:
                        continue;

                    events = buf[:i].split(line_break)
                    f2bf[f] += i + len(line_break)
                    for evt in events:
                        parse_event( evt )

            except:
                pass

        time.sleep(0.1)

def parse_event(evt):
    print evt

follow()
