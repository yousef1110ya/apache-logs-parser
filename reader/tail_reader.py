import time


def follow(filepath):

    with open(filepath, "r") as file:

        file.seek(0, 2)

        while True:

            line = file.readline()

            if not line:

                time.sleep(0.1)

                continue

            yield line
