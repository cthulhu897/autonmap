import pandas as pd
dataFrame = pd.read_csv("openPorts.csv")
print(dataFrame)
print("<------------>")

lines = []
with open('unic.txt') as f:
    lines = f.readlines()

print(lines)

for ip in lines:
    # condition mask
    mask = dataFrame['ip'] == ip.replace("\n", "")
    
    # new dataframe with selected rows
    df_new = pd.DataFrame(dataFrame[mask])
    print(df_new)
    fileName = ip.replace("\n", "") +'.csv'
    df_new['port'].to_csv(fileName, index=False, header=False)
    print("---\n")
