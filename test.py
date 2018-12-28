from gbkzipfile  import GBKZipFile
z = GBKZipFile('a.zip', 'r')  
print (z.read(z.namelist()[0]) )