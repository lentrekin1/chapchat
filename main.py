from flask import Flask, render_template, session, request, redirect, flash, make_response
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import current_user, login_user, LoginManager, UserMixin, logout_user
from flask_mail import Mail, Message
import csv, hashlib, hmac, time, random, os, string, json, pickle, base64
from datetime import datetime

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'tqwefsdd3.,edmk;vkflqjdmsndakd'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin'
socketio = SocketIO(app)
socketio.init_app(app, cors_allowed_origins='*')  # ['https://'+url, 'http://'+url])

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'lancee478@gmail.com'
app.config['MAIL_PASSWORD'] = base64.b64decode(b'RW50cmVraW41IQ==').decode()
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

default_hash = b'%\xb0p\x18\x85\xaa<\x19\x11\xcc\x97L\xea\xad\xcf\xcf\x9e\xb5+\xe0\xa9;Uv"\xb3|\x96H\x81\xe4\xb2'
default_salt = b'L\xb6\x113"\x90)\x08\x14\x07\x17b1I\x0c'
default_last_requested = 25201
default_pass = {'phash': default_hash, 'psalt': default_salt, 'prequested': default_last_requested}
admin_email = 'lancee478@gmail.com'
pass_file = 'adminpass.pickle'
admin_pass_timeout = 30  # minutes
pass_reset_token = None
token_size = 50
phash, psalt, prequested = None, None, None


def get_creds():
    global phash, psalt, prequested
    if not os.path.isfile(pass_file):
        with open(pass_file, 'wb') as f:
            pickle.dump(default_pass, f)
    with open(pass_file, 'rb') as f:
        creds = pickle.load(f)
        phash = creds['phash']
        psalt = creds['psalt']
        prequested = creds['prequested']
        del creds


get_creds()


def save_creds(h, s, r):
    with open(pass_file, 'wb') as f:
        pickle.dump({'phash': h, 'psalt': s, 'prequested': r}, f)
    get_creds()


class room():
    def __init__(self, name, invites):
        self.max_len = 100
        self.key_size = 10
        self.name = name
        self.people = []
        self.messages = []
        self.key = None
        self.make_key()
        self.invites_enabled = invites

    def make_key(self):
        self.key = ''.join(random.choices(string.ascii_letters, k=self.key_size))

    def add_msg(self, msg):
        if len(self.messages) >= self.max_len:
            del self.messages[0]
        self.messages.append(msg)

    def get_names(self):
        return [x['nickname'] for x in self.people]

    def add_user(self, usr):
        self.people.append(usr)

    # todo for kicking users: user must have tracker cookie to connect to chatrooms (set on login/invite), use that tracker cookie to keep user kicked rather than sid
    # todo use that tracker cookie as sid value rather than request.sid
    # todo add option for what to do when creator leaves in newroom.html then do that when creator leaves
    def remove_user(self, nick=None, sid=None):
        for i in range(len(self.people)):
            if self.people[i]['nickname' if nick else 'sid'] == nick if nick else sid:
                del self.people[i]
                break

    def get_user(self, nick=None, sid=None):
        for i in range(len(self.people)):
            if self.people[i]['nickname' if nick else 'sid'] == nick if nick else sid:
                return self.people[i]


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
            r.append(room(str(i[0]), True if i[1] == 'true' else False))
        return r


# todo add method from admin panel to delete/save rooms (save to csv file)
# todo figure out why invalid ssl from GCP
rooms = load_rooms()


def get_room(name):
    for r in rooms:
        if r.name == name:
            return r
    return None


min_len = 3
max_len = 15

rooms_dir = '/rooms/'
invite_dir = '/invite/'
reset_dir = '/admin/reset/'
banned_rooms = []


# todo add validation for user msgs?

def val_pw(pw):
    if pw:
        if len(pw) < 20:
            if len(pw) > 8:
                if hmac.compare_digest(phash, hashlib.pbkdf2_hmac('sha256', pw.encode(), psalt, 100000)):
                    return True
                else:
                    return 'Incorrect password'
            else:
                return 'Please enter a longer password'
        else:
            return 'Please enter a shorter password'
    else:
        return 'Please provide a password'


def val_room(name, real=True):
    if name:
        if min_len < len(name):
            if max_len > len(name):
                if name.isalnum():
                    if not name in banned_rooms:
                        if not real or not get_room(name):
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
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), psalt, 100000)


def timestamp():
    return datetime.now().strftime('%I:%M %p')


def make_reset_token():
    return ''.join(random.choices(string.ascii_letters, k=token_size))


def setup_pass_change():
    global pass_reset_token
    save_creds(phash, psalt, time.time())
    pass_reset_token = make_reset_token()


def exists(data, check):
    try:
        if data['data'][check]:
            return True
        return False
    except:
        return False


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.before_request
def make_session_permanent():
    session.permanent = True


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
        print(request.form)
        name = request.form.get('roomname')
        result = val_room(name, real=False)
        if result == True:
            rooms.append(room(name, True if request.form.get('enableInvites') else False))
            if request.form.get('enableAdmin'):
                resp = make_response(redirect(rooms_dir + str(name)))
                resp.set_cookie('room-key', get_room(name).key)
                return resp
            else:
                return redirect(rooms_dir + str(name))
        else:
            flash(result)
    return render_template('newroom.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect('/admin')


# todo when admin pw change, old users still connected - fix
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if isinstance(val_pw(request.cookies.get('pass')), str):
        session.clear()
        logout_user()
    if current_user.is_authenticated:
        return render_template('admin.html', rooms=rooms, totalnum=get_total_users())
    if request.method == 'POST':
        result = val_pw(request.form.get('pass'))
        if result == True:
            login_user(User('admin'))
            return render_template('admin.html', rooms=rooms, totalnum=get_total_users())
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
            if request.form.get('nickname') in get_room('mainchat').get_names():
                flash('This name is taken for this room')
            else:
                return redirect(rooms_dir + 'mainchat')
        elif 'specific' in request.form.keys():
            if request.form.get('room'):
                if get_room(request.form.get('room')):
                    if request.form.get('nickname') in get_room(request.form.get('room')).get_names():
                        flash('This name is taken for this room')
                    else:
                        return redirect(rooms_dir + request.form.get('room'))
                else:
                    flash('Room not found')
            else:
                flash('Please enter a room key')
        elif 'newroom' in request.form.keys():
            return redirect('/newroom')
        # print(list(request.form.keys()))
    return render_template('login.html')


@app.route(rooms_dir + '<name>')
def priv_room(name):
    if get_room(name):
        if 'realtime-chat-nickname' in request.cookies:
            roomLeader = 'none'
            people = []
            if 'room-key' in request.cookies and request.cookies.get('room-key') == get_room(name).key:
                people = get_room(name).get_names()
                roomLeader = ''
            return render_template('chat.html', roomName=name, people=people, roomLeader=roomLeader,
                                   invites='' if get_room(name).invites_enabled else 'none')
        else:
            return redirect('/login')
    return render_template('404.html'), 404


# todo make sure all options choosen by room creator shown on admin view

@app.route(invite_dir + '<name>', methods=['GET', 'POST'])
def enter_room(name):
    if get_room(name) and get_room(name).invites_enabled:
        if request.method == 'POST':
            result = val_nick(request.form.get('nickname'))
            if result == True:
                if request.form.get('nickname') in get_room(name).get_names():
                    flash('This name is taken for this room')
                else:
                    return redirect(rooms_dir + name)
            flash(result)
        return render_template('invite.html', roomName=name)
    return render_template('404.html'), 404


# todo working on changing admin pass - actually send pass reset email - maybe use flask-mail - https://pythonbasics.org/flask-mail/
@app.route(reset_dir, methods=['GET', 'POST'])
def reset_pass():
    global pass_reset_token
    token = request.args.get('token')
    if pass_reset_token and token == pass_reset_token:
        if time.time() - prequested < admin_pass_timeout * 60:
            if request.method == 'POST':
                if request.form.get('newpass') == request.form.get('confirmpass'):
                    result = val_pw(request.form.get('newpass'))
                    if result == 'Incorrect password':
                        save_creds(get_hash(request.form.get('newpass')), psalt, time.time())
                        pass_reset_token = None
                        flash('Password successfully changed')
                        # resp = make_response(redirect('/admin'))
                        # resp.set_cookie('pass', request.form.get('newpass'))
                        # return resp
                    elif result == True:
                        flash('New password cannot be old password')
                    else:
                        flash(result)
                else:
                    flash('Passwords must match')
            return render_template('passreset.html')
        else:
            pass_reset_token = None
    return redirect('/login')


@socketio.on('message')
def chat_message(data):
    data['data']['timestamp'] = timestamp()
    data['data']['type'] = 'message'
    get_room(data['data']['room']).add_msg(data)
    emit('message', {'data': data['data']}, room=data['data']['room'])


# todo add logging
# todo make it so admin/maybe room creator can allow/disallow sending pics - on creation or later or both?
# todo make it so can see full photo when zoomed in on mobile
@socketio.on('photo')
def photo(data):
    if data['data']['room'] != 'mainchat':
        data['data']['timestamp'] = timestamp()
        data['data']['type'] = 'photo'
        get_room(data['data']['room']).add_msg(data)
        emit('message', {'data': data['data']}, room=data['data']['room'])


@socketio.on('connect')
def test_connect():
    emit('my response', {'data': 'Connected', 'count': 0})


@socketio.on('leave')
def leave(data, admin=False):
    data['data']['timestamp'] = timestamp()
    leave_room(data['data']['room'])
    if admin and exists(data, 'pass') and val_pw(data['data']['pass']) == True:
        # print('admin dc')
        pass
    else:
        get_room(data['data']['room']).add_msg({'data': {'message': f'{data["data"]["user"]} has left the server',
                                                         'timestamp': timestamp(), 'type': 'announcement'}})
        get_room(data['data']['room']).remove_user(nick=data["data"]["user"])
        # print(f'user {data["data"]["user"]} left room {data["data"]["room"]}')
        emit('message', {'data': {'message': f'{data["data"]["user"]} has left the server', 'timestamp': timestamp(),
                                  'type': 'announcement'}}, room=data['data']['room'])


@socketio.on('set connection')
def set_connect(data, admin=False):
    join_room(data['data']['user'])
    for m in get_room(data['data']['room']).messages:
        emit('message', m, room=data['data']['user'])
    leave_room(data['data']['user'])
    join_room(data['data']['room'])
    if admin and exists(data, 'pass') and val_pw(data['data']['pass']) == True:
        print('admin connect')
    else:
        get_room(data['data']['room']).add_msg({'data': {'message': f'{data["data"]["user"]} has joined the server',
                                                         'timestamp': timestamp(), 'type': 'announcement'}})
        get_room(data['data']['room']).add_user({'nickname': data["data"]["user"], 'sid': request.sid})
        print(f'{request.cookies["realtime-chat-nickname"]} has joined the room {data["data"]["room"]}')
        emit('message', {'data': {'message': f'{data["data"]["user"]} has joined the server', 'timestamp': timestamp(),
                                  'type': 'announcement'}}, room=data['data']['room'])


@socketio.on('kick user')
def kick_user(data):
    if exists(data, 'key') and exists(data, 'room') and data['data']['key'] == get_room(data['data']['room']).key:
        emit('message', {
            'data': {'message': f'{data["data"]["kick"]} was kicked by {data["data"]["user"]}',
                     'timestamp': timestamp(),
                     'type': 'announcement'}}, room=data['data']['room'])
        leave_room(data['data']['room'], sid=get_room(data['data']['room']).get_user(nick=data['data']['kick'])['sid'])
        # print(f'{data["data"]["kick"]} was kicked by {data["data"]["user"]} from {data["data"]["room"]}')


@socketio.on('admin connect')
def admin_conect(data):
    data['data']['timestamp'] = timestamp()
    if exists(data, 'pass') and val_pw(data['data']['pass']) == True:
        set_connect(data, admin=True)


@socketio.on('admin disconnect')
def admin_disconect(data):
    data['data']['timestamp'] = timestamp()
    if exists(data) and val_pw(data['data']['pass']) == True:
        leave(data, admin=True)


@socketio.on('admin announcement')
def announce(data):
    data['data']['timestamp'] = timestamp()
    data['data']['type'] = 'announcement'
    if exists(data) and val_pw(data['data']['pass']) == True:
        get_room(data['data']['room']).add_msg(data)
        emit('message', data, room=data['data']['room'])


@socketio.on('admin photo')
def announce(data):
    data['data']['timestamp'] = timestamp()
    data['data']['type'] = 'announcement photo'
    if exists(data) and val_pw(data['data']['pass']) == True:
        get_room(data['data']['room']).add_msg(data)
        emit('message', data, room=data['data']['room'])


@socketio.on('change admin pass')
def change_pass(data):
    data['data']['timestamp'] = timestamp()
    if exists(data, 'pass') and val_pw(data['data']['pass']) == True:
        setup_pass_change()
        msg = Message(
            'ChapChat admin password reset link',
            sender='lancee478@gmail.com',
            recipients=['lancee478@gmail.com']
        )
        msg.body = f'Here is the ChapChat admin password reset link. It is valid for {admin_pass_timeout} minutes.' \
                   f'\n{request.url_root[:-1] + reset_dir}?token={pass_reset_token}'
        mail.send(msg)
        join_room('pass change')
        emit('pass change confirm', {'data': {'email': admin_email, 'timeout': str(admin_pass_timeout)}},
             room='pass change')
        leave_room('pass change')


if __name__ == '__main__':
    socketio.run(app, port=80)

##############
# sooooooo it appears to work but u have to connect w/ vpn (https://chap-chat-test-305403.wm.r.appspot.com)
# prob start actually making this good
##############


######### old ############
# stil getting error 400 from socketio but only on gcp not local
# seems to get better after a few min
# see https://stackoverflow.com/questions/65144726/app-engine-flask-socketio-server-cors-allowed-origins-header-is-missing
# and https://stackoverflow.com/questions/65189422/flask-docker-container-socketio-issues
