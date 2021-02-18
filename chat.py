#!/bin/env python
from app import create_app, socketio, hostname
import subprocess, threading, time


app = create_app(debug=True)

def expose():
    c = subprocess.Popen(['staqlab-tunnel', '5000', 'hostname='+hostname])
    print(c.communicate())

if __name__ == '__main__':
    t = threading.Thread(target=expose, args=())
    t.start()
    time.sleep(5)
    #socketio.run(app)
    from flask import Flask
    app = Flask(__name__)
    @app.route('/')
    def b():
        return 'home'
    @app.route('/run')
    def r():
        return 'run'
    app.run()

