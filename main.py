import os
import string
import subprocess
import threading
import time
from datetime import datetime

from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config["SECRET_KEY"] = 'qwed!R2eas@R#$4a'
socketio = SocketIO(app)
socketio.init_app(app, cors_allowed_origins="*")

# Establish global variables for tracking users
users = []                                          # list of users
channels = ["Main Channel", "Second Channel"]       # list of channels

# Dictionary of list of dictionaries
# Contains channel -> messages -> (text, username, AND timestamp)
messages_dict = {
    "Main Channel": [
        {
            "message": "Welcome, friends!",
            "username": "Tbone",
            "timestamp": "2019-04-07"
        },
        {
            "message": "Hi, nice to meet you :)!",
            "username": "Georgie",
            "timestamp": "2019-04-07"
        }],
    "Second Channel": [
        {
            "message": "hello!",
            "username": "random_person_123",
            "timestamp": "2019-03-06"
        }
    ]
}
message_limit = 100


@app.route("/")
def index():
    return render_template("index.html",
                           users=users,
                           channels=channels)


@socketio.on("confirm login")
def confirm_login(data):
    """ If the user connects with the local storage login method, ensure that
        the 'users' list is updated in the server.
    """
    username = data["username"]
    if username not in users:
        users.append(username)
        app.logger.info(f"Appended username: '{username}'")
    app.logger.info("Confirmed login.")


@socketio.on("user logged in")
def log_in(data):
    """ Adds username to the server list of users. This is for
        form-submitted data.
    """
    username = data["username"]
    if username not in users:
        users.append(username)
        app.logger.info(f"\nLogging {username} in. Users: \n{users}")
        emit("new user",
             {"username": username}, broadcast=False)
    else:
        app.logger.info(f"Username '{username}' taken.")
        emit("username taken", broadcast=False)
#maybe prob is emit() isnt sending to right address?

@socketio.on("new channel created")
def create_new_channel(data):
    """ Checks whether a channel can be created. If so, this updates the
        channel list and broadcasts the new channel.
    """
    channel = clean_up_channel_name(data["channel"])

    app.logger.info(
        "HINT: Running the 'create new channel' "
        f"function with channel: {channel}.")
    # If the channel is new, add it
    if channel not in channels:
        if valid_channel(channel):
            channels.append(channel)
            # Add the channel item to the messages dicationary
            messages_dict[channel] = []
            app.logger.info(
                f"If-statement success with \n\n{channels}!"
                "\n\nEmitting 'add channel'\n\n")
            emit("add channel", {"channel": channel}, broadcast=True)
        else:
            # If the channel is NOT a valid name
            emit("invalid channel name", broadcast=False)
    else:
        app.logger.info("If statement failure!")
        emit("channel creation failed", broadcast=False)


@socketio.on("move to channel")
def move_user_to_room(data):
    """ Moves the user to the specified channel. Checks to see if the channel
        exists in the server list of channels.
    """
    channel = data["channel"]
    messages = messages_dict[channel]
    if channel in channels:
        emit("enter channel room", {
            "channel": channel, "messages": messages})


@socketio.on("new message")
def new_message(data):
    """ Processes the new message and stores it into the server list of
        messages given the room name. Broadcast the room and message.
    """
    message, channel, username = (
        data["message"], data["channel"], data["username"])
    timestamp = get_timestamp_trunc()

    messages_dict[channel].append({
        "message": message,
        "username": username,
        "timestamp": timestamp
    })

    if len(messages_dict[channel]) > message_limit:
        # Remove the first element if more than message_limit messages
        messages_dict[channel] = messages_dict[channel][1:]

    data = {
        "channel": channel,
        "message": message,
        "timestamp": timestamp,
        "username": username
    }
    emit("message broadcast", data, broadcast=True)


@socketio.on("verify channel")
def verify_channel(data):
    """ Verifies whether the channel exists or not.
    """
    channel = data["channel"]
    if channel not in channels:
        emit("default channel")
    else:
        # do nothing if the channel exists
        pass


def get_timestamp_trunc():
    """ Grabs the timestamp rounds the decimal point to deciseconds.
        For example:
        '2019-07-04 00:18:39.532357' becomes
        '2019-07-04 00:18:39.5'
    """
    timestamp = str(datetime.now())
    return timestamp[:-5]


def clean_up_channel_name(text: str) -> str:
    """ Clean up extra spaces and remove punctuation from channel name.
    """
    # Remove punctuation
    text = text.strip().translate(str.maketrans('', '', string.punctuation))

    # Remove extra spaces by splitting spaces and rejoining
    text = ' '.join(text.split())

    return text


def valid_channel(channel: str) -> bool:
    """ Checks whether the channel is a valid channel name.
    """
    if channel == "":
        return False
    return True

hostname='chap-chats'

def expose():
    c = subprocess.Popen(['C:\\Users\\lance\\PycharmProjects\\chapchat\\staqlab-tunnel.exe', '8080', 'hostname=' + hostname])
    print(c.communicate())

reveal = False
debug = True

if __name__ == "__main__":
    if reveal:
        t = threading.Thread(target=expose, args=())
        t.start()
        time.sleep(20)
    socketio.run(app, debug=debug)#, port=8080)
    #todo y tf dont files refresh when i restart local server (ie index.js)
