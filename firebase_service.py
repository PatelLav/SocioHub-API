import json
import os
import firebase_admin
from firebase_admin import credentials, messaging

firebase_json = os.getenv("FIREBASE_CREDENTIALS")

print("Firebase env found:", firebase_json is not None)

if not firebase_json:
    raise Exception("FIREBASE_CREDENTIALS missing")

cred_dict = json.loads(firebase_json)

cred = credentials.Certificate(cred_dict)

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)


async def firebase_send_push(token, title, body):

    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        token=token,
    )

    messaging.send(message)
