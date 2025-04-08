import pandas as pd

s = pd.Series([3, -5, 7, 4], index=['a', 'b', 'c', 'd'])

data = {
    'Country': ['Belgium', 'India', 'Brazil'], 'Capital': ['Brussels', 'New Delhi', 'Brasilia'],
    'Population': [11190846, 1303171035, 207847528]
}
df = pd.DataFrame(data)

col1 = pd.Series(['Belgium', 'India', 'Brazil'])
col2 = pd.Series(['Brussels', 'New Delhi', 'Brasilia'])
col3 = pd.Series([11190846, 1303171035, 2])
df = pd.DataFrame([col1, col2, col3]).transpose()

df.columns = ['Country', 'Capital', 'Population']

# Save your existing DataFrame first
# df.to_csv('file.csv')

# Then read it
# pd.read_csv('file.csv', nrows=5)

# Save your existing DataFrame first
df.to_excel('myDataFrame.xlsx', sheet_name='Sheet1')

# Then read it
pd.read_excel('myDataFrame.xlsx')

# You can also select multiple columns
population_by_country = df[['Country', 'Population']]
print("\nCountry and population:")
print(population_by_country)

print("Shape:", df.shape)
print("Index:", df.index)
print("Columns:", df.columns)
print("\nInfo:")
df.info()
print("\nNon-null counts:")
print(df.count())