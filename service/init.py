import secrets

from werkzeug.security import generate_password_hash

from app import categories
from main import db
from models import User, Joke


def init_application():
    populate_database()
    setup_review()


def setup_review():
    for category in categories.category_list:
        db.session.add(Joke(under_review=True, category=category,
                            content="Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin ornare magna eros, eu pellentesque tortor vestibulum ut. Maecenas non massa sem. Etiam finibus odio quis feugiat facilisis."))
    db.session.commit()


def populate_database():
    dad_jokes()
    blondes()
    political()
    family()
    sports()
    animal()
    user = User(name="admin", password=generate_password_hash(secrets.token_hex(16), method='scrypt'))
    db.session.add(user)
    db.session.commit()


def dad_jokes():
    jokes = [
        "I'm afraid for the calendar. Its days are numbered.",
        "My wife said I should do lunges to stay in shape. That would be a big step forward.",
        "Why do fathers take an extra pair of socks when they go golfing? In case they get a hole in one!",
        "Singing in the shower is fun until you get soap in your mouth. Then it's a soap opera.",
        "What do a tick and the Eiffel Tower have in common? They're both Paris sites.",
        "What do you call a fish wearing a bowtie? Sofishticated.",
        "How do you follow Will Smith in the snow? You follow the fresh prints.",
        "If April showers bring May flowers, what do May flowers bring? Pilgrims.",
        "I thought the dryer was shrinking my clothes. Turns out it was the refrigerator all along.",
        "How does dry skin affect you at work? You don’t have any elbow grease to put into it."
    ]
    for j in jokes:
        db.session.add(Joke(category="Dad", content=j))


def blondes():
    jokes = [
        "A blonde, a redhead, and a brunette were all lost in the desert. They found a lamp and rubbed it. A genie popped out and granted them each one wish. The redhead wished to be back home. Poof! She was back home. The brunette wished to be at home with her family. Poof! She was back home with her family. The blonde said, 'Awwww, I wish my friends were here.'",
        "Two blondes fell down a hole. One said, 'It's dark in here isn't it?' The other replied, 'I don't know; I can't see.'",
        "Blonde: 'What does IDK stand for?' Brunette: 'I don’t know.' Blonde: 'OMG, nobody does!'"
    ]
    for j in jokes:
        db.session.add(Joke(category="Blonde", content=j))


def political():
    jokes = [
        "Q: Have you heard about McDonald’s new Obama Value Meal? A: Order anything you like and the guy behind you has to pay for it.",
        "Politicians and diapers have one thing in common: they should both be changed regularly… and for the same reason.",
        "If con is the opposite of pro, then is Congress the opposite of progress?"
    ]

    for j in jokes:
        db.session.add(Joke(category="Political", content=j))


def family():
    jokes = [
    ]

    for j in jokes:
        db.session.add(Joke(category="Family", content=j))


def sports():
    jokes = [
        'Three guys go to a ski lodge, and there aren\'t enough rooms, so they have to share a bed. In the middle of the night, the guy on the right wakes up and says, "I had this wild, vivid dream of getting a hand job!" The guy on the left wakes up, and unbelievably, he\'s had the same dream, too. Then the guy in the middle wakes up and says, "That\'s funny, I dreamed I was skiing!"',
        'A guy and his wife are sitting and watching a boxing match on television. The husband sighs and complains, “This is disappointing. It only lasted for 30 seconds!” “Good,” replied his wife. “Now you know how I always feel.”'
        , 'Golfer: "Do you think my game is improving?"',
        'A football coach walked into the locker room before a game, looked over to his star player and said, "I\'m not supposed to let you play since you failed math, but we need you in there. So what I have to do is ask you a math question, and if you get it right, you can play." The player agreed, and the coach looked into his eyes intently and asks, "Okay, now concentrate... what is two plus two?" The player thought for a moment and then he answered, "4?" "Did you say 4?!?" the coach exclaimed, excited that he got it right. At that, all the other players on the team began screaming, "Come on coach, give him another chance!"'
    ]
    for j in jokes:
        db.session.add(Joke(category="Sports", content=j))


def animal():
    jokes = [
        'A boy is selling fish on a corner. To get his customers\' attention, he is yelling, "Dam fish for sale! Get your dam fish here!" A pastor hears this and asks, "Why are you calling them \'dam fish.\'" The boy responds, "Because I caught these fish at the local dam." The pastor buys a couple fish, takes them home to his wife, and asks her to cook the dam fish. The wife responds surprised, "I didn\'t know it was acceptable for a preacher to speak that way." He explains to her why they are dam fish. Later at the dinner table, he asks his son to pass the dam fish. He responds, "That\'s the spirit, Dad! Now pass the f*cking potatoes!"'
        , "Q: Why did the witches' team lose the baseball game? A: Their bats flew away.",
        "Q: Can a kangaroo jump higher than the Empire State Building? A: Of course. The Empire State Building can't jump."
        , "Q: Why couldn't the leopard play hide and seek? A: Because he was always spotted."
    ]
    for j in jokes:
        db.session.add(Joke(category="Animal", content=j))
