import sqlite3

con = sqlite3.connect('vulnscan.db')
c = con.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS scans
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    status_code INTEGER,
                    headers TEXT)''')

con.commit()
con.close()
