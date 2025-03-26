from flask import Flask, request
import sqlite3
import json
import os

app = Flask(__name__)

# Create a table if it doesn't exist
DB_FILEPATH = 'blocked_domains.db'
if os.path.exists(DB_FILEPATH):
    os.remove(DB_FILEPATH)

conn = sqlite3.connect(DB_FILEPATH)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        body TEXT
    )
''')
conn.commit()
conn.close()

@app.route('/dga', methods=['POST', 'GET'])
def index():
    if request.method == 'POST':
        # method = request.method
        # path = request.path
        # headers = str(request.headers)
        body = request.json
        body = json.dumps(body)

        # Check if the request already exists in the database
        conn = sqlite3.connect(DB_FILEPATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM requests WHERE body = ?
        ''', (body, ))
        existing_request = cursor.fetchone()

        if existing_request:
            conn.close()
            return 'Request already exists in the database!'

        # Store the request in the database
        cursor.execute('''
            INSERT INTO requests (body)
            VALUES (?)
        ''', (body, ))
        conn.commit()
        conn.close()

        return 'Request stored in the database!'

    elif request.method == 'GET':
        # Retrieve stored requests from the database
        conn = sqlite3.connect(DB_FILEPATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM requests')
        stored_requests = cursor.fetchall()
        conn.close()

        # Format and display the stored requests
        result = []
        for req in stored_requests:
            result.append({
                "ID": req[0],
                "Body": json.loads(req[1]),
            })

        return json.dumps(result)

if __name__ == '__main__':
    app.run()