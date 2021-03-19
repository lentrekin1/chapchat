import base64
import csv
import hashlib
import hmac
import os
import pickle
import random
import string
import time
import re
import logging
from datetime import datetime

from flask import Flask, render_template, session, request, redirect, flash
from flask_login import current_user, login_user, LoginManager, UserMixin, logout_user
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit, join_room, leave_room

from flask_session import Session
#emojis etc - not working on my phone
#fix ssl warning
#typing notifications
#use deadspace in ui (mainly on pc) - background?
#todo leader collapse has no background - bad?
#leader status didnt save on jays phone

if not os.path.isdir('logs'):
    os.mkdir('logs')

token_size = 50

def make_token(size=token_size):
    return ''.join(random.choices(string.ascii_letters, k=size))

log_token = make_token(size=7)
filename = 'logs\{:%Y_%m_%d_%H}-' + log_token + '.log'
logging.basicConfig(filename=filename.format(datetime.now()),
                            format='%(asctime)s | %(levelname)-8s | %(message)s', filemode='w')
logger = logging.getLogger("ChapChat")
logger.setLevel(logging.DEBUG)

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'tqwefsdd3.,edmk;vkflqjdmsndakd'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin'
socketio = SocketIO(app, manage_session=False)
socketio.init_app(app, cors_allowed_origins='*')  # ['https://'+url, 'http://'+url])

app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

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
phash, psalt, prequested = None, None, None
admin_sids = []

leader_link_timeout = 24  # hours


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

def exists(data, check):
    try:
        if data[check] or data['data'][check]:
            return True
        return False
    except:
        return False


class room():
    def __init__(self, name, invites, photos, leaders, subinvites, key, creator_id):
        self.max_len = 100
        self.key_size = 10
        self.name = name
        self.people = []
        self.messages = []
        self.banned = []
        self.key = key if key else make_token()
        self.invites_enabled = invites
        self.photos_enabled = photos
        self.other_leaders = leaders
        self.subinvites = subinvites
        self.creator = {'userID': creator_id} if creator_id else None
        self.leaders = []
        self.pending_leaders = []
        self.token = None
        self.token_time = None
        self.set_token()

    def set_token(self, refresh_time=True):
        self.token = make_token()
        if refresh_time:
            self.token_time = time.time()

    def add_msg(self, msg):
        if len(self.messages) >= self.max_len:
            del self.messages[0]
        self.messages.append(msg)

    def add_leader(self, usr, creator=False):
        if self.get_leader(userID=usr['userID']):
            if 'sid' not in usr and 'sid' in self.get_leader(userID=usr['userID']):
                usr['sid'] = self.get_leader(userID=usr['userID'])['sid']
            self.remove_leader(userID=usr['userID'])
        if exists(usr, 'nickname') and self.get_leader(nick=usr['nickname']):
            if 'sid' not in usr and 'sid' in self.get_leader(nick=usr['nickname']):
                usr['sid'] = self.get_leader(nick=usr['nickname'])['sid']
            self.remove_leader(nick=usr['nickname'])
        self.leaders.append(usr)
        if creator or (creator and usr['userID'] == self.creator['userID']):
            self.creator = usr

    def get_leaders(self):
        return self.leaders

    def get_names(self, low=False):
        if not low:
            return [x['nickname'] for x in self.people]
        else:
            return [x['nickname'].lower() for x in self.people]

    def add_user(self, usr):
        if self.get_user(nick=usr['nickname']):
            self.remove_user(nick=usr['nickname'])
        if self.get_user(userID=usr['userID']):
            self.remove_user(userID=usr['userID'])
        if self.get_leader(userID=usr['userID']):
            self.remove_leader(userID=usr['userID'])
            self.add_leader(usr)
        self.people.append(usr)

    def remove_leader(self, nick=None, userID=None):
        if nick:
            nick = nick.lower()
        for i in range(len(self.leaders)):
            check = self.leaders[i]['nickname' if nick else 'userID']
            if nick:
                check = check.lower()
            if check == nick if nick else userID:
                del self.leaders[i]
                break

    def remove_user(self, nick=None, userID=None):
        if nick:
            nick = nick.lower()
        for i in range(len(self.people)):
            check = self.people[i]['nickname' if nick else 'userID']
            if nick:
                check = check.lower()
            if check == nick if nick else userID:
                del self.people[i]
                break

    def get_leader(self, nick=None, userID=None):
        if nick:
            nick = nick.lower()
        for i in range(len(self.leaders)):
            check = self.leaders[i]['nickname' if nick else 'userID']
            if nick:
                check = check.lower()
            if check == nick if nick else userID:
                return self.leaders[i]

    def get_user(self, nick=None, userID=None):
        if nick:
            nick = nick.lower()
        for i in range(len(self.people)):
            check = self.people[i]['nickname' if nick else 'userID']
            if nick:

                check = check.lower()
            if check == nick if nick else userID:
                return self.people[i]

    def is_banned(self, uid):
        if uid in [x['userID'] for x in self.banned]:
            return True
        return False


def load_rooms():
    r = []
    if not os.path.isdir('info'):
        os.mkdir('info')
    if not os.path.isfile('info/rooms.csv'):
        with open('info/rooms.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['mainchat', 'True', 'False', 'False', 'False', 'None', 'None'])
    with open('info/rooms.csv', 'r') as f:
        reader = csv.reader(f)
        for i in reader:
            r.append(room(str(i[0]), i[1] == 'True', i[2] == 'True', i[3] == 'True', i[4] == 'True',
                          None if i[5] == 'None' else i[5], None if i[6] == 'None' else i[6]))
        return r


def save_room(r, save_key=True, save_creator=True):
    with open('info/rooms.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(
            [r.name, r.invites_enabled, r.photos_enabled, r.other_leaders, r.subinvites, r.key if save_key else 'None',
             r.creator['userID'] if save_creator else 'None'])


# todo add method from admin panel to delete/save rooms (save to csv file)
# todo figure out why invalid ssl from GCP - https://stackoverflow.com/a/42255561 - helpful?
rooms = load_rooms()


def get_room(name):
    for r in rooms:
        if r.name.lower() == name.lower():
            return r
    return None


min_len = 3
max_len = 15

rooms_dir = '/rooms/'
invite_dir = '/invite/'
reset_dir = '/admin/reset/'
leader_dir = '/addleader'
banned_rooms = []


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


def val_room(name):
    if name:
        if min_len <= len(name):
            if max_len >= len(name):
                if re.match("^[A-Za-z0-9_-]*$", name):
                    if not name.lower() in banned_rooms:
                        if not get_room(name):
                            return True
                        else:
                            return 'Room name already in use'
                    else:
                        return 'Room name is not allowed'
                else:
                    return 'Room name can only have letters, numbers, dashes, and underscores'
            else:
                return 'Please enter a shorter room name'
        else:
            return 'Please enter a longer room name'
    else:
        return 'Please enter room name'


def val_nick(nick):
    if nick:
        if min_len <= len(nick):
            if max_len >= len(nick):
                if re.match("^[A-Za-z0-9_-]*$", nick):
                    return True
                else:
                    return 'Nickname can only have letters, number, dashes, and underscores'
            else:
                return 'Please enter a shorter nickname'
        else:
            return 'Please enter a longer nickname'
    else:
        return 'Please enter a nickname'


class User(UserMixin):
    def __init__(self, id=None):
        self.id = id


def get_total_users():
    t = 0
    for r in rooms:
        t += len(r.people)
    return t


def get_hash(pw):
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), psalt, 100000)


def timestamp():
    return str(datetime.utcnow()) + 'Z'


def setup_pass_change():
    global pass_reset_token
    save_creds(phash, psalt, time.time())
    pass_reset_token = make_token()


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.before_request
def make_session_permanent():
    if not exists(session, 'userID'):
        session['userID'] = ''.join(random.choices(string.ascii_letters, k=30))
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
        if not exists(session, 'userName'):
            return redirect('/login')
        name = request.form.get('roomname')
        result = val_room(name)
        if result == True:
            session['chatroom'] = name
            rooms.append(room(name, request.form.get('enableInvites') == 'on', request.form.get('enablePhotos') == 'on',
                              request.form.get('addLeaders') == 'on', request.form.get('subAddLeaders') == 'on', None,
                              session['userID']))
            save_room(get_room(name), save_key=True)
            app.logger.info(f'{session["userName"]} (userID = {session["userID"]} created the room {name}')
            if request.form.get('enableAdmin'):
                session['chatroom-key'] = get_room(name).key
                get_room(name).add_leader({'nickname': session["userName"], 'userID': session['userID']}, creator=True)
                get_room(name).add_user({'nickname': session["userName"], 'userID': session['userID']})
                # resp = make_response(redirect(rooms_dir + str(name)))
                # resp.set_cookie('room-key', get_room(name).key)
                # return resp
            # else:
            return redirect(rooms_dir + str(name))
        else:
            flash(result)
    if not exists(session, 'userName'):
        return redirect('/login')
    return render_template('newroom.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect('/admin')


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if isinstance(val_pw(session['master-key']), str):
        session.clear()
        logout_user()
    if current_user.is_authenticated:
        return render_template('admin.html', rooms=rooms, totalnum=get_total_users())
    if request.method == 'POST':
        result = val_pw(request.form.get('master-key'))
        if result == True:
            session['master-key'] = request.form.get('master-key')
            session['userName'] = 'admin'
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
            if request.form.get('nickname').lower() in get_room('mainchat').get_names(low=True):
                flash('This name is taken for this room')
            else:
                session['userName'] = request.form.get('nickname')
                session['chatroom'] = 'mainchat'
                return redirect(rooms_dir + 'mainchat')
        elif 'specific' in request.form.keys():
            if request.form.get('room'):
                if get_room(request.form.get('room')):
                    if request.form.get('nickname').lower() in get_room(request.form.get('room')).get_names(low=True):
                        flash('This name is taken for this room')
                    else:
                        session['userName'] = request.form.get('nickname')
                        session['chatroom'] = request.form.get('room')
                        return redirect(rooms_dir + request.form.get('room'))
                else:
                    flash('Room not found')
            else:
                flash('Please enter a room key')
        elif 'newroom' in request.form.keys():
            session['userName'] = request.form.get('nickname')
            return redirect('/newroom')
    return render_template('login.html')


@app.route(rooms_dir + '<name>')
def priv_room(name):
    if get_room(name):
        if 'userName' in session and not get_room(name).is_banned(session['userID']):
            if session['userID'] in get_room(session['chatroom']).pending_leaders:
                session['chatroom-key'] = get_room(name).key
                get_room(session['chatroom']).pending_leaders.remove(get_room(session['chatroom']).get_leader(nick=session['userName'])['userID'])
            roomLeader = 'none'
            people = []
            inviteLeaders = 'none'
            if 'chatroom-key' in session and session['chatroom-key'] == get_room(name).key:
                get_room(session['chatroom']).add_leader({'userID': session['userID'], 'nickname': session['userName']})
                people = get_room(name).get_names()
                roomLeader = ''
                if get_room(name).other_leaders == get_room(name).subinvites == True or (get_room(name).other_leaders and session['userID'] == get_room(name).creator['userID']):
                    inviteLeaders = ''
            return render_template('chat.html', roomName=name, people=people, roomLeader=roomLeader,
                                   invites='' if get_room(name).invites_enabled else 'none',
                                   photos='' if get_room(name).photos_enabled else 'none',
                                   inviteLeaders=inviteLeaders)
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
                if request.form.get('nickname') in get_room(name).get_names(low=True):
                    flash('This name is taken for this room')
                else:
                    session['userName'] = request.form.get('nickname')
                    session['chatroom'] = name
                    return redirect(rooms_dir + name)
            flash(result)
        return render_template('invite.html', roomName=name)
    return render_template('404.html'), 404


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
                        session['pass'] = request.form.get('newpass')
                        session['name'] = 'admin'
                        save_creds(get_hash(request.form.get('newpass')), psalt, time.time())
                        pass_reset_token = None
                        flash('Password successfully changed')
                        # resp = make_response(redirect('/admin'))
                        # resp.set_cookie('master-key', request.form.get('newpass'))
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


'''@app.route(leader_dir, methods=['GET', 'POST'])
def add_leader():
    chatroom = request.args.get('chatroom')
    token = request.args.get('token')
    if get_room(chatroom) and get_room(chatroom).other_leaders:
        if token == get_room(chatroom).token:
            if time.time() - get_room(chatroom).token_time < leader_link_timeout * 60 * 60:
                get_room(chatroom).add_leader({'userID': session['userID']})
                session['chatroom-key'] = get_room(chatroom).key
                #todo should token always be only one use or nah?
                if not get_room(chatroom).subinvites:
                    get_room(chatroom).set_token(refresh_time=False)
                return render_template('addleader.html', roomName=chatroom, invalid=not get_room(chatroom).subinvites)
            else:
                return 'This leader invite token has expired, please get a new one'
    return redirect('/login')'''


@socketio.on('message')
def chat_message(data):
    if not get_room(session['chatroom']).is_banned(session['userID']):
        if data['data']['message'] != '' and not data['data']['message'].isspace():
            data['data']['timestamp'] = timestamp()
            data['data']['type'] = 'message'
            data['data']['user'] = session['userName']
            # get_room(data['data']['room']).add_msg(data)
            get_room(session['chatroom']).add_msg(data)
            emit('message', data, room=session['chatroom'].lower())


@socketio.on('photo')
def photo(data):
    if not get_room(session['chatroom']).is_banned(session['userID']):
        if get_room(session['chatroom']).photos_enabled and data['data']['photo'] != '' and not data['data']['photo'].isspace():
            data['data']['timestamp'] = timestamp()
            data['data']['type'] = 'photo'
            data['data']['user'] = session['userName']
            get_room(session['chatroom']).add_msg(data)
            join_room(room=session['userID'])
            emit('recv')
            leave_room(room=session['userID'])
            emit('message', {'data': data['data']}, room=session['chatroom'].lower())


@socketio.on('connect')
def test_connect():
    # if session['userID'] not in get_room(session['chatroom']).banned:
    emit('my response', {'data': 'Connected', 'count': 0})


@socketio.on('leave')
def leave(data, admin=False):
    data['data']['timestamp'] = timestamp()
    leave_room(session['chatroom'].lower())
    if admin and exists(session, 'master-key') and val_pw(session['master-key']) == True:
        app.logger.info(f'Admin (userID={session["userID"]}) disconnected from room {session["chatroom"]}')
    else:
        get_room(session['chatroom']).add_msg({'data': {'message': f'{session["userName"]} has left the server',
                                                        'timestamp': timestamp(), 'type': 'announcement'}})
        get_room(session['chatroom']).remove_user(nick=session["userName"])
        app.logger.info(f'User {session["userName"]} (userID={session["userID"]}) left room {session["chatroom"]}')
        emit('message', {'data': {'message': f'{session["userName"]} has left the server', 'update': 'removal',
                                  'name': session['userName'], 'timestamp': timestamp(),
                                  'type': 'announcement'}}, room=session['chatroom'].lower())


@socketio.on('set connection')
def set_connect(data=None, sess=session, admin=False):
    if not get_room(session['chatroom']).is_banned(session['userID']):
        join_room(sess['userName'])
        for m in get_room(sess['chatroom']).messages:
            emit('message', m, room=sess['userName'])
        emit('message', {'data': {'type': 'caught up', 'for': sess['userID'], 'timestamp': timestamp()}}, room=sess['userName'])
        leave_room(sess['userName'])

        join_room(sess['chatroom'].lower())
        if admin and exists(sess, 'master-key') and val_pw(sess['master-key']) == True:
            #emit('user list',
            #     {'data': {'users': ','.join([x['nickname'] for x in get_room(session['chatroom']).people])}}, room=sess['chatroom'])
            app.logger.info(f'Admin (userID={session["userID"]}) connected to room {session["chatroom"]}')
        else:
            #if exists(sess, 'room-key') and sess['room-key'] == get_room(sess['chatroom']).key:
            #    emit('user list', {'data': {'users': ','.join([x['nickname'] for x in get_room(session['chatroom']).people])}})

            get_room(session['chatroom']).add_leader(
                {'userID': session['userID'], 'nickname': session['userName'], 'sid': request.sid})

            get_room(sess['chatroom']).add_msg({'data': {'message': f'{sess["userName"]} has joined the server',
                                                         'timestamp': timestamp(), 'type': 'announcement'}})
            get_room(sess['chatroom']).add_user(
                {'nickname': sess["userName"], 'userID': sess['userID'], 'sid': request.sid})
            if sess['userID'] in [x['userID'] for x in get_room(sess['chatroom']).get_leaders()]:
                get_room(sess['chatroom']).add_leader(
                    {'nickname': sess["userName"], 'userID': sess['userID'], 'sid': request.sid})
            app.logger.info(f'{sess["userName"]} (userID={session["userID"]}) has joined the room {sess["chatroom"]}')
            emit('message', {'data': {'message': f'{sess["userName"]} has joined the server', 'update': 'addition',
                                      'name': session['userName'], 'timestamp': timestamp(),
                                      'type': 'announcement'}}, room=sess['chatroom'].lower())
    else:
        join_room(sess['userID'])
        emit('announcement', {'data': {'message': 'You have been banned from this room', 'timestamp': timestamp(),
                                       'type': 'announcement'}}, room=sess['userID'])
        leave_room(sess['userID'])


@socketio.on('kick user')
def kick_user(data):
    if not get_room(session['chatroom']).is_banned(session['userID']):
        if exists(session, 'chatroom-key') and exists(session, 'chatroom') and session['chatroom-key'] == get_room(
                session['chatroom']).key:
            if data['data']['kick'] in get_room(session['chatroom']).get_names(low=True):
                app.logger.info(
                    f'{data["data"]["kick"]} (userID={get_room(session["chatroom"]).get_user(nick=data["data"]["kick"])["userID"]}) was kicked by {session["userName"]} (userID={session["userID"]}) from {session["chatroom"]}')
                join_room(get_room(session['chatroom']).get_user(nick=data['data']['kick'])['userID'],
                          sid=get_room(session['chatroom']).get_user(nick=data['data']['kick'])['sid'])
                emit('message', {
                    'data': {'message': f'You were kicked by {session["userName"]}',
                             'timestamp': timestamp(),
                             'type': 'announcement'}},
                     room=get_room(session['chatroom']).get_user(nick=data['data']['kick'])['userID'])
                leave_room(get_room(session['chatroom']).get_user(nick=data['data']['kick'])['userID'],
                           sid=get_room(session['chatroom']).get_user(nick=data['data']['kick'])['sid'])
                leave_room(session['chatroom'],
                           sid=get_room(session['chatroom']).get_user(nick=data['data']['kick'])['sid'])
                get_room(session['chatroom']).banned.append(
                    get_room(session['chatroom']).get_user(nick=data['data']['kick']))
                emit('message', {
                    'data': {'message': f'{data["data"]["kick"]} was kicked by {session["userName"]}',
                             'update': 'removal',
                             'name': session['userName'],
                             'timestamp': timestamp(),
                             'type': 'announcement'}}, room=session['chatroom'].lower())


@socketio.on('add leader')
def add_leader(data):
    if session['chatroom-key'] == get_room(session['chatroom']).key:
        if get_room(session['chatroom']).subinvites or session['userID'] == get_room(session['chatroom']).creator[
            'userID']:
            get_room(session['chatroom']).add_leader(get_room(session['chatroom']).get_user(nick=data['data']['user']))
            app.logger.info(
                f"User {data['data']['user']} (userID = {get_room(session['chatroom']).get_user(nick=data['data']['user'])['userID']}) was made a leader of {session['chatroom']} by {session['userName']} (userID = {session['userID']})")
            join_room(get_room(session['chatroom']).get_user(nick=data['data']['user'])['userID'], sid=get_room(session['chatroom']).get_user(nick=data['data']['user'])['sid'])
            emit('given leader', {'data': {'message': f'You were made a leader of {session["chatroom"]} by {session["userName"]}', 'for': get_room(session['chatroom']).get_user(nick=data['data']['user'])['userID'], 'timestamp': timestamp(), 'type': 'announcement'}}, room=get_room(session['chatroom']).get_user(nick=data['data']['user'])['userID'])
            get_room(session['chatroom']).pending_leaders.append(get_room(session['chatroom']).get_user(nick=data['data']['user'])['userID'])
            leave_room(get_room(session['chatroom']).get_user(nick=data['data']['user'])['userID'], sid=get_room(session['chatroom']).get_user(data['data']['user'])['sid'])
            #get_room(session['chatroom']).add_leader({'userID': session['userID']})
            #session['chatroom-key'] = get_room(chatroom).key

'''@socketio.on('get leader link')
def send_leader_link():
    if session['chatroom-key'] == get_room(session['chatroom']).key:
        if get_room(session['chatroom']).subinvites or session['userID'] == get_room(session['chatroom']).creator[
            'userID']:
            if time.time() - get_room(session['chatroom']).token_time > leader_link_timeout * 60 * 60:
                get_room(session["chatroom"]).set_token()
            leader_link = f'{request.url_root[:-1] + leader_dir}?token={get_room(session["chatroom"]).token}&chatroom={session["chatroom"].lower()}'
            join_room(session['userID'])
            emit('leader link', {'data': {'link': leader_link}}, room=session['userID'])
            leave_room(session['userID'])'''


@socketio.on('admin connect')
def admin_conect(data):
    global admin_sid
    data['data']['timestamp'] = timestamp()
    if exists(session, 'master-key') and val_pw(session['master-key']) == True:
        admin_sids.append(request.sid)
        session['chatroom-key'] = get_room(data['room']).key
        set_connect(sess=session, admin=True)


@socketio.on('admin disconnect')
def admin_disconect(data):
    data['data']['timestamp'] = timestamp()
    if exists(session, 'master-key') and val_pw(session['master-key']) == True:
        admin_sids.remove(request.sid)
        leave(sess=session, admin=True)


@socketio.on('admin announcement')
def announce(data):
    data['data']['timestamp'] = timestamp()
    data['data']['type'] = 'announcement'
    if exists(session, 'master-key') and val_pw(session['master-key']) == True:
        if data['data']['message'] != '' and not data['data']['message'].isspace():
            get_room(session['chatroom']).add_msg(data)
            emit('message', data, room=session['chatroom'].lower())


@socketio.on('admin photo')
def announce(data):
    data['data']['timestamp'] = timestamp()
    data['data']['type'] = 'announcement photo'
    if exists(session, 'master-key') and val_pw(session['master-key']) == True:
        if data['data']['message'] != '' and not data['data']['message'].isspace():
            get_room(session['chatroom']).add_msg(data)
            emit('message', data, room=session['chatroom'].lower())


@socketio.on('change admin pass')
def change_pass(data):
    data['data']['timestamp'] = timestamp()
    if exists(session, 'master-key') and val_pw(session['master-key']) == True:
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
