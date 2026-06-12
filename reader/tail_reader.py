import os
import time


def follow(filepath, sleep_seconds=0.1):

    file = None

    while True:

        if file is None:
            try:
                file = open(
                    filepath,
                    "r",
                    encoding="utf-8",
                    errors="replace"
                )
                file.seek(
                    0,
                    os.SEEK_END
                )
            except FileNotFoundError:
                time.sleep(
                    sleep_seconds
                )
                continue

        line = file.readline()

        if line:
            yield line
            continue

        try:
            if os.path.getsize(filepath) < file.tell():
                file.close()
                file = None
        except FileNotFoundError:
            file.close()
            file = None

        time.sleep(
            sleep_seconds
        )
