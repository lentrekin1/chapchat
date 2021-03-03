from flask import Flask, render_template, session, request, redirect
from flask_socketio import SocketIO, emit, join_room
import csv

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'wretrgf4t$R@#efdvbyj5w'
socketio = SocketIO(app)
socketio.init_app(app, cors_allowed_origins='*')#['https://'+url, 'http://'+url])

def load_rooms():
  r = []
  with open('info/rooms.csv', 'r') as f:
    reader = csv.reader(f)
    for i in reader:
      r.append(i)
    return r

rooms = load_rooms()

#todo in chat.html: add check for io.connect to connect to private room
#todo add checking  to make sure input is valid according to rules i havnt made yet for all val_ funcs

def val_room(name):
  if name:
    return True

def val_nick(nick):
  if nick:
    return True

@app.route('/')
def chat():
  #todo add check cookies to see if in private room
  if 'realtime-chat-nickname' in request.cookies and val_nick(request.cookies['realtime-chat-nickname']):
    return redirect('/mainchat')
  else:
    return redirect('/login')

'''@app.route('/redir')
def redir():
  print(request.form)
  print(request.form.get("room"))
  if request.form.get('specific'):
    print('wert')
  return 'e'
  '''

'''@app.route('/mainchat')
def mainchat():
  return render_template('chat.html')'''

@app.errorhandler(404)
def err_404(e):
  return render_template('404.html'), 404

#todo finish creating new room screen and implement multiple rooms/pws/ etc
@app.route('/newroom', methods=['GET', 'POST'])
def newroom():
  if request.method == 'POST':
    name = request.form.get('roomname')
    if name and val_room(name):
        rooms.append(name)
        return redirect('/'+str(name))
    #print(request.form.get('roomname'))

  return render_template('newroom.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    print(request.form)
    if 'main' in request.form.keys() and request.form.get('nickname'):
      return redirect('/mainchat')
    elif 'specific' in request.form.keys() and request.form.get('room') and request.form.get('nickname'):
      return redirect('/' + request.form.get('room'))
    elif 'newroom' in request.form.keys():
      return redirect('/newroom')
    else:
      return render_template('login.html')
    #print(list(request.form.keys()))
  #todo add test to see if login info valid - prob on both client and server
  return render_template('login.html')

#todo add x has LEFT the server message
#todo sending messages to main chat works- do priv chats
#todo add check so user cant impersonate server - prob make server msgs red or smthn
@app.route('/<name>')
def priv_room(name):
  print(request.cookies)
  if name in rooms or name == 'mainchat':
    if 'realtime-chat-nickname' in request.cookies:
      print(f'{request.cookies["realtime-chat-nickname"]} has joined the server')
      socketio.emit('announcement', {'data': f'{request.cookies["realtime-chat-nickname"]} has joined the server'}, broadcast=True, namespace='/mainchat')
      return render_template('chat.html')
    else:
      return redirect('/login')
  return render_template('404.html'), 404

@socketio.on('message', namespace='/mainchat')
def chat_message(message):
  print("message = ", message)
  print(message['data'])
  emit('message', {'data': message['data']}, broadcast=True)

@socketio.on('connect', namespace='/mainchat')
def test_connect():
  emit('my response', {'data': 'Connected', 'count': 0})

#todo start implementing desired features (ex. user count, admin panel, multiple rooms?, etc.)

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