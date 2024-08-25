import time, re

fn = "C:/.../SoftwareCPEComp.txt"
filename = "C:/.../SoftwareCPEExt.txt"

lines = open(fn, encoding="utf-8").read().split("\n")

start = time.time()

length = len(lines)
for i in range(length):
    if lines[i].split("|")[6:]:
        line = lines[i].encode("cp1252", "ignore").decode("cp1252")

        lines[i] = ""
        software = line.split("|")[0:6]
        software = [re.sub(r"^\s+|\s+$", "", item) for item in software]
        software = "|".join(software)
        cpes = line.split("|")[6:]
        order = 1
        for cpe in cpes:
            lines.append(software + "|" + str(order) + "|" + cpe)
            order += 1

print(time.time() - start)
lines = list(filter(None, lines))
print(time.time() - start)

# Se escribe la lista en el archivo de texto
with open(filename, "w") as f:
    for item in lines:
        f.write("%s\n" % item)

print(time.time() - start)

import pyodbc

conn = pyodbc.connect(
    r"Driver={SQL Server};"
    r"Server=localhost;"
    r"Database=Software;"
    r"Trusted_Connection=yes;"
)

cursor = conn.cursor()

print(time.time() - start)

# Se da la orden de eliminar la tabla (después se creará de nuevo)
cursor.execute("DROP TABLE SoftwareCPE;")
# Se transmite esa orden
conn.commit()

# Se crea de nuevo la tabla
cursor.execute(
    "CREATE TABLE SoftwareCPE (Vendor nvarchar(MAX), VendorFiltrado nvarchar(MAX), VendorOriginal nvarchar(MAX), ProductFiltrado nvarchar(MAX), ProductOriginal nvarchar(MAX), Version nvarchar(MAX), Orden tinyint, CPE nvarchar(MAX))"
)
conn.commit()

# Se realiza un bulk insert para subir el fichero de texto
cursor.execute(
    """
BULK INSERT SoftwareCPE
    FROM 'C:/.../SoftwareCPEExt.txt'
    WITH 
        (FIELDTERMINATOR = '|',
         ROWTERMINATOR = '\n')"""
)
conn.commit()

print(time.time() - start)

# Se cierra la conexión
cursor.close()
conn.close()
