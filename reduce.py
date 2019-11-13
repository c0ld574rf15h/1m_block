import pandas as pd

df = pd.read_csv('./top-1m.csv')

f = open('./input.txt', 'w')

for name in df.domain:
    f.write(name + '\n')