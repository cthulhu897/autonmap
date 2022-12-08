'''
Python script that get from csv ip an ports open 
'''

import os
import sys
import subprocess
try:
    import pandas as pd                  
except ImportError:
    try:
        import pip
        pip.main(['install', '--user', 'pandas'])
        import pandas as pd 
    except:
        print("[!] pandas is not installed")
        print("pip install pandas")
        exit(1)

def main(fileName):
    if not os.path.exists(fileName):
        print(f"[!] File {fileName} not exist")
        exit(1)

    dataFrame = pd.read_csv(fileName)

    unicIPs = dataFrame.drop_duplicates(subset=["ip"], keep="first")

    for ip in unicIPs['ip']:
        mask = dataFrame['ip'] == ip
        
        df_new = pd.DataFrame(dataFrame[mask])

        fileName = ip.replace("\n", "") +'.csv'
        df_new['port'].to_csv(fileName, index=False, header=False)
    
    rc = subprocess.call("./script.sh")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("./parser.py file.csv")
        exit(1)
    fileName = sys.argv[1]
    main(fileName)
 