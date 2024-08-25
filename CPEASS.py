import re, time, pickle, os, itertools, torch, logging
import pandas as pd
from difflib import SequenceMatcher
import multiprocessing as mp
import numpy as np

vendor = ""
filepath = "C:/.../CVE-NIST/officialCPEdictionary_v2.3.txt"
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

fn = "C:/.../SoftwareCPEComp.txt"

with open("C:/.../UniqueCPEVendor.txt", encoding="utf-8") as f:
    cpeuniquelist = f.readlines()
cpeuniquelist = [x.strip() for x in cpeuniquelist]

logger = mp.get_logger()


def CPEFinder(key, q):
    global vendor, cpe, df_mask, cpeuniquelist
    if key.split("|")[0] != vendor:
        vendor = key.split("|")[0]
        mask = cpe["Vendor"].str.contains("^" + vendor, case=False)
        df_mask = list(cpe[mask]["cpe23uri"])
        if not df_mask:
            logger.warning("escribo")
            closestvendor = sorted(
                cpeuniquelist,
                key=lambda x: SequenceMatcher(None, x, key.split("|")[0]).quick_ratio(),
                reverse=True,
            )[0]
            mask = cpe["Vendor"].str.contains("^" + closestvendor, case=False)
            df_mask = list(cpe[mask]["cpe23uri"])

    software = " ".join(
        list(dict.fromkeys((re.sub(r" +", " ", key.replace("|", " "))).split()))
    )
    results = sorted(
        df_mask,
        key=lambda x: SequenceMatcher(None, x, software).quick_ratio(),
        reverse=True,
    )[:20]
    str_soft = r"" + key + "|" + "|".join(results)
    q.put(str_soft)
    return str_soft


def listener(q):
    with open(fn, "w", encoding="utf-8") as f:
        while 1:
            try:
                m = q.get()
                if m == "kill":
                    break
                f.write(str(m) + "\n")
                f.flush()
            except Exception:
                import sys, traceback

                traceback.print_exc(file=sys.stderr)


def main():

    filepathread = "C:/.../SoftwareFiltradoGeneral.csv"
    df_read = pd.read_csv(
        filepathread,
        dtype=str,
        names=[
            "publisher",
            "publisher_filtrado",
            "publisher_original",
            "name",
            "name_original",
            "version",
        ],
        sep="|",
        encoding="latin-1",
    )
    df_read = df_read.replace(np.nan, "", regex=True)
    list_read = (df_read.agg("|".join, axis=1)).to_list()

    manager = mp.Manager()
    q = manager.Queue()
    pool = mp.Pool()
    watcher = pool.apply_async(listener, (q,))

    start = time.time()
    jobs = []
    for i in list_read:
        job = pool.apply_async(CPEFinder, (i, q))
        jobs.append(job)

    for job in jobs:
        job.get()

    q.put("kill")
    pool.close()
    pool.join()

    print(time.time() - start)


if __name__ == "__main__":
    main()
