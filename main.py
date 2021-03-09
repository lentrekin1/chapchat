from flask import Flask, render_template, session, request, redirect, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import current_user, login_user, LoginManager, UserMixin
import csv, hashlib, hmac, time, random, os
from datetime import datetime

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'wretrgf4t$R@#efdvbyj5w'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin'
socketio = SocketIO(app)
socketio.init_app(app, cors_allowed_origins='*')#['https://'+url, 'http://'+url])

hash = b'>\xf4\x88\xd5\xc464\x9a\x14\xb7n\xdc\xbf\xaa\xa2\xed\xb5|P\xa3bq\xb1\xa6b[\xcd\xe6_b7\xff'
salt = b'L\xb6\x113"\x90)\x08\x14\x07\x17b1I\x0c'

class room():
  def __init__(self, name):
    self.name = name
    self.people = []

def load_rooms():
  r = []
  if not os.path.isdir('info'):
    os.mkdir('info')
  if not os.path.isfile('info/rooms.csv'):
    with open('info/rooms.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['mainchat'])
  with open('info/rooms.csv', 'r') as f:
    reader = csv.reader(f)
    for i in reader:
      r.append(room(str(i[0])))
    return r
#todo add method from admin panel to delete/save rooms (save to csv file)
#todo figure out why invalid ssl from GCP
rooms = load_rooms()

def get_room(name):
  for r in rooms:
    if r.name == name:
      return r
  raise Exception(f'Room {name} not found')

min_len = 3
max_len = 15

banned_rooms = ['admin']

#todo add validation for user msgs?

def val_pw(pw):
  if pw:
      if len(pw) < 20:
        if hmac.compare_digest(hash, hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 100000)):
          return True
        else:
          return 'Incorrect password'
      else:
        return 'Please enter a shorter password'
  else:
    return 'Please provide a password'

def val_room(name):
  if name:
    if min_len < len(name):
      if max_len > len(name):
        if name.isalnum():
          if not name in banned_rooms:
            if not get_room(name):
              return True
            else:
              return 'Room name already in use'
          else:
            return 'Room name is not allowed'
        else:
          return 'Room name can only have letters and numbers'
      else:
        return 'Please enter a shorter room name'
    else:
      return 'Please enter a longer room name'
  else:
    return 'Please enter room name'

def val_nick(nick):
  if nick:
    if min_len < len(nick):
      if max_len > len(nick):
        if nick.isalnum():
          return True
        else:
          return 'Nickname can only have letters and numbers'
      else:
        return 'Please enter a shorter nickname'
    else:
      return 'Please enter a longer nickname'
  else:
    return 'Please enter a nickname'

class User(UserMixin):
  def __init__(self, id):
    self.id = id

def get_id(self):
  return 'admin'

def get_total_users():
  t = 0
  for r in rooms:
    t += len(r.people)
  return t

def get_hash(pw):
  return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 100000)

def timestamp():
  return datetime.now().strftime('%I:%M %p')

@login_manager.user_loader
def load_user(user_id):
  return User(user_id)

@app.route('/')
def chat():
  '''if 'realtime-chat-nickname' in request.cookies and val_nick(request.cookies['realtime-chat-nickname']):
    if "oldroom" in request.cookies and request.cookies["oldroom"]:
      if request.cookies['oldroom'] in rooms:
        return redirect('/' + request.cookies["oldroom"])
      else:
        return
    else:
      return redirect('/mainchat')
  else:'''
  return redirect('/login')

@app.errorhandler(404)
def err_404(e):
  return render_template('404.html'), 404

@app.route('/newroom', methods=['GET', 'POST'])
def newroom():
  if request.method == 'POST':
    name = request.form.get('roomname')
    result = val_room(name)
    if result == True:
        rooms.append(room(name))
        #get_room(request.form.get('roomname')).people.append(request.cookies.get('realtime-chat-nickname'))
        return redirect('/'+str(name))
    else:
        flash(result)
    #print(request.form.get('roomname'))

  return render_template('newroom.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
  if current_user.is_authenticated:
    return render_template('admin.html', rooms=rooms, totalnum=get_total_users())
  if request.method == 'POST':
    result = val_pw(request.form.get('pass'))
    if result == True:
      login_user(User('admin'))
      return render_template('admin.html', rooms=rooms, totalnum=get_total_users(), phash=get_hash(request.form.get('pass')))
    else:
      flash(result)
  return render_template('adminlogin.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    result = val_nick(request.form.get('nickname'))
    if not request.form.get('nickname') or not result == True:
      flash(result)
    elif 'main' in request.form.keys():
        #get_room('mainchat').people.append(request.form.get('nickname'))
        return redirect('/mainchat')
    elif 'specific' in request.form.keys():
      if request.form.get('room'):
        if get_room(request.form.get('room')):
          #get_room(request.form.get('room')).people.append(request.form.get('nickname'))
          return redirect('/' + request.form.get('room'))
        else:
          flash('Room not found')
      else:
        flash('Please enter a room key')
    elif 'newroom' in request.form.keys():
      return redirect('/newroom')
    #print(list(request.form.keys()))
  return render_template('login.html')

@app.route('/<name>')
def priv_room(name):
  if get_room(name):
    if 'realtime-chat-nickname' in request.cookies:
      return render_template('chat.html')
    else:
      return redirect('/login')
  return render_template('404.html'), 404

@socketio.on('message')
def chat_message(message):
  message['data']['timestamp'] = timestamp()
  emit('message', {'data': message['data']}, room=message['data']['room'])

#todo add logging
#todo make it so admin/maybe room creator can allow/disallow sending pics - on creation or later or both?
#todo make it so can see full photo when zoomed in on mobile
@socketio.on('photo')
def photo(data):
  if data['data']['room'] != 'mainchat':
    data['data']['timestamp'] = timestamp()
    emit('photo', {'data': data['data']}, room=data['data']['room'])

@socketio.on('connect')
def test_connect():
  emit('my response', {'data': 'Connected', 'count': 0})

@socketio.on('leave')
def leave(data, admin=False):
  data['data']['timestamp'] = timestamp()
  leave_room(data['data']['room'])
  if admin and val_pw(data['data']['pass']) == True:
    #print('admin dc')
    pass
  else:
    get_room(data['data']['room']).people.remove(data["data"]["user"])
    #print(f'user {data["data"]["user"]} left room {data["data"]["room"]}')
    emit('announcement', {'data': {'message': f'{data["data"]["user"]} has left the server', 'timestamp': timestamp()}}, room=data['data']['room'])

@socketio.on('set connection')
def set_connect(data, admin=False):
  join_room(data['data']['room'])
  if admin and val_pw(data['data']['pass']) == True:
    print('admin connect')
  else:
    get_room(data['data']['room']).people.append(data["data"]["user"])
    print(f'{request.cookies["realtime-chat-nickname"]} has joined the server')
    emit('announcement', {'data': {'message': f'{data["data"]["user"]} has joined the server', 'timestamp': timestamp()}}, room=data['data']['room'])

@socketio.on('admin connect')
def admin_conect(data):
  data['data']['timestamp'] = timestamp()
  if val_pw(data['data']['pass']) == True:
    set_connect(data, admin=True)

@socketio.on('admin disconnect')
def admin_disconect(data):
  data['data']['timestamp'] = timestamp()
  if val_pw(data['data']['pass']) == True:
    leave(data, admin=True)

@socketio.on('admin announcement')
def announce(message):
  message['data']['timestamp'] = timestamp()
  print(message)
  if val_pw(message['data']['pass']) == True:
    emit('announcement', {'data': message['data']}, room=message['data']['room'])

@socketio.on('admin photo')
def announce(message):
  message['data']['timestamp'] = timestamp()
  print(message)
  if val_pw(message['data']['pass']) == True:
    emit('announcement photo', {'data': message['data']}, room=message['data']['room'])

if __name__ == '__main__':
  socketio.run(app)




##############
# sooooooo it appears to work but u have to connect w/ vpn (https://chap-chat-test-305403.wm.r.appspot.com)
# prob start actually making this good
##############



######### old ############
#stil getting error 400 from socketio but only on gcp not local
#seems to get better after a few min
# see https://stackoverflow.com/questions/65144726/app-engine-flask-socketio-server-cors-allowed-origins-header-is-missing
#and https://stackoverflow.com/questions/65189422/flask-docker-container-socketio-issues