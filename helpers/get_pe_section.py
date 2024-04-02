import pefile

'''

    Helper information:

        This helper take the data of a specific PE section

'''

def get_pe_section(file, section):
    pe = pefile.PE(data=file)
    section_data = None
    
    # Scanning the argument "section" of the file.
    for sec_dados in pe.sections:
        if bytes(section, encoding='utf8') in sec_dados.Name:
            section_data = sec_dados.get_data()

    return section_data