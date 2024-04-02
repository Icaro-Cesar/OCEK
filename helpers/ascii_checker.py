
'''

    Helper information:

        This helper check if the data is ASCI

'''

def ascii_checker(string):
    
    return all(character < 128 or character == 0 for character in string)