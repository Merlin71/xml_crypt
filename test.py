from XmlEncryption.XmlEncryption import xml_encrypt, xml_decrypt
from XmlEncryption.XmlEncryption import xml_obfuscate, xml_reverse_obfuscate

if __name__ == '__main__':
    xml_encrypt("plain.xml", "cypher.bin", "password")
    xml_file = xml_decrypt("cypher.bin", "password")
    xml_file.write("plain_restored_enc.xml")

    xml_obfuscate("plain.xml", "cypher.obf")
    xml_file = xml_reverse_obfuscate("cypher.obf")
    xml_file.write("plain_restored_obf.xml")






