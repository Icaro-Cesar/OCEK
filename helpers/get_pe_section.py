import pefile

def get_pe_section(file, section):
    pe = pefile.PE(data=file)
    section_data = None
    
    # Varrendo a seção "section" do arquivo
    for sec_dados in pe.sections:
        if bytes(section, encoding='utf8') in sec_dados.Name:
            section_data = sec_dados.get_data()

    return section_data