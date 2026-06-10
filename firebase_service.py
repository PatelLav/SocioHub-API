import json
import os
import firebase_admin

from firebase_admin import credentials
from firebase_admin import messaging

cred_dict = json.loads(
    os.environ["FIREBASE_CREDENTIALS"]
)

cred = credentials.Certificate(cred_dict)

firebase_admin.initialize_app(cred)


async def send_push(token, title, body):

    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        token=token,
    )

    messaging.send(message)
