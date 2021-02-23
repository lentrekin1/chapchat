from flask import Flask, render_template, session, request
from flask_socketio import SocketIO, emit, join_room

#url = 'chap-chat-test-305403.wm.r.appspot.com'
#url = '127.0.0.1'

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'wretrgf4t$R@#efdvbyj5w'
socketio = SocketIO(app)
socketio.init_app(app, cors_allowed_origins='*')#['https://'+url, 'http://'+url])

@app.route('/')
def chat():
  return render_template('chat.html')

@app.route('/login')
def login():
  return render_template('login.html')

@socketio.on('message', namespace='/chat')
def chat_message(message):
  print("message = ", message)
  emit('message', {'data': message['data']}, broadcast=True)

@socketio.on('connect', namespace='/chat')
def test_connect():
  emit('my response', {'data': 'Connected', 'count': 0})



if __name__ == '__main__':
  socketio.run(app)



##############
#
# todo sooooooo it appears to work but u have to connect w/ vpn (https://chap-chat-test-305403.wm.r.appspot.com)
# prob start actually making this good
##############



######### old ############
#todo stil lgetting error 400 from socketio but only on gcp not local
#seems to get better after a few min
# see https://stackoverflow.com/questions/65144726/app-engine-flask-socketio-server-cors-allowed-origins-header-is-missing
#and https://stackoverflow.com/questions/65189422/flask-docker-container-socketio-issues