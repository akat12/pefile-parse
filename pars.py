import pefile

pe = pefile.PE('gmodule-2.dll')
print "File headers \n"
print pe.FILE_HEADER
print "Optional headers \n"
print pe.OPTIONAL_HEADER

print "sections \n"
for section in pe.sections:
    print section.Name,hex(section.VirtualAddress)

print "Import table \n"

for entry in pe.DIRECTORY_ENTRY_IMPORT:
  print entry.dll
  for imp in entry.imports:
    print '\t', hex(imp.address), imp.name

print "Export table \n"
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
  print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal