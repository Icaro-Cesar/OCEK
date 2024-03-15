def ascii_checker(s):
    return all(c < 128 or c == 0 for c in s)