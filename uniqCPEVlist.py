import re, time, pickle
import pandas as pd
import numpy as np
from difflib import SequenceMatcher

filepath = (
    "C:/Users/Alejandro Perales/Documents/CVE-NIST/officialCPEdictionary_v2.3.txt"
)
cpe = pd.read_csv(
    filepath,
    dtype=str,
    names=[
        "title",
        "lang",
        "cpe23uri",
        "Part",
        "Vendor",
        "Product",
        "Version",
        "Update_sw",
        "Edition",
        "Language",
        "SW_Edition",
        "Target_SW",
        "Target_HW",
        "Other",
        "Autonumber",
    ],
    sep="|",
    encoding="latin-1",
)

cpelist = cpe["Vendor"].values.tolist()

cpeunique = list(set(cpelist[1:]))

cpeunique = [w.replace("\\", "\\\\") for w in cpeunique]

cpeunique.sort()

with open("UniqueCPEVendor.txt", "w") as f:
    for item in cpeunique:
        re.compile(item)
        f.write("%s\n" % item)
