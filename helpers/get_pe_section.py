import pefile

'''

    Helper information:

        This helper take the data of a specific PE section

'''

def get_pe_section(file_path, section):
    with open(file_path, 'rb') as f:
        pe = pefile.PE(data=f.read()) 

    section_data = None
    for sec_dados in pe.sections:
        if bytes(section, encoding='utf8') in sec_dados.Name:
            section_data = sec_dados.get_data()

    return section_data