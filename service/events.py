import threading
from abc import ABC, abstractmethod

import app

lock = threading.Lock()
counter = 0


class AbstractEvent(ABC, str):
    @abstractmethod
    def hidden(self):
        pass


class PublicEvent(AbstractEvent):
    hidden = False

    def __init__(self, category):
        global counter
        self.category = category
        with lock:
            self.id = counter
            counter += 1


class AdminEvent(AbstractEvent):
    hidden = True

    def __init__(self, category):
        self.category = category


eventhandler = dict()


def register_event(event, handler, admin=True):
    if admin:
        eventhandler[AdminEvent(event)] = handler
    else:
        eventhandler[PublicEvent(event)] = handler
