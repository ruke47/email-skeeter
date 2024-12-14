import email
import email.policy
import json
import logging
import os
import re
import typing as t

from atproto import Client, models

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

class SimpleEmail:
    def __init__(self, sender:str, subject:str, body:str):
        self.sender = sender
        self.subject = subject
        self.body = body

def lambda_handler(event, context):
    log.debug(f"Got Event: {json.dumps(event)}")
    mail = get_simplified_email(event)
    log.info(f"Email from {mail.sender}: {mail.subject}\n{mail.body}")

    user, password, approved_senders = load_environment()

    if mail.sender in approved_senders:
        st_text = extract_alert_data(mail)
        if st_text:
            create_thread(user, password, st_text)
    else:
        log.warning(f"Got email from unapproved sender: {mail.sender}")


def load_environment() -> (str, str, str):
    user = os.getenv("USERNAME")
    password = os.getenv("PASSWORD")
    approved_senders = os.getenv("APPROVED_SENDERS").split(",")
    if not user or not password or not approved_senders:
        missing = []
        if not user:
            missing.append("USERNAME")
        if not password:
            missing.append("PASSWORD")
        if not approved_senders:
            missing.append("APPROVED_SENDERS")
        log.warning(f"Unable to load environment: {missing}")
        exit(-1)

    return user, password, approved_senders

def get_simplified_email(event) -> SimpleEmail | None:
    sns_message = deep_get(event, "Records", 0, "Sns", "Message")
    if not sns_message:
        log.warning("Couldn't parse event as SNS message.")
        return

    ses_notification = json.loads(sns_message)
    sender = deep_get(ses_notification, "mail", "source")
    email_content = deep_get(ses_notification, "content")
    if not email_content or not sender:
        log.warning("Couldn't parse event as SES notification.")
        return

    mail = email.message_from_string(email_content, policy=email.policy.default)
    return SimpleEmail(sender, mail.get('Subject', failobj=''), mail.get_body('plain').get_content().strip())

st_signoffs = r"(?:(:?See something suspicious\?)|(?:Plan your trip or find alternate service options.))"
st_email_pattern = re.compile(r'(?P<body>.*?)\s+' + st_signoffs + '.*', re.DOTALL)
email_address_pattern = re.compile(r'\S+@\S+.com')
subject_prefixes = ["Reminder: ", "All Clear: ", "Resolved: ", "{{p_subject}}"]
def extract_alert_data(mail:SimpleEmail) -> str | None :
    result = st_email_pattern.match(mail.body)

    # If the email doesn't match the pattern I expect, I don't want to publish it
    if not result:
        log.debug(f"Does not match Sound Transit Pattern")
        return

    body = result.group('body').strip()

    # If the email contains my email address, I don't want to publish it
    if email_address_pattern.findall(body):
        log.warning(f"Not posting; contains an email address")
        return

    # If the subject starts with a prefix, pretend that it doesn't
    simple_subject = mail.subject
    for prefix in subject_prefixes:
        if simple_subject.startswith(prefix):
            simple_subject = simple_subject[len(prefix):].strip()

    # Sometimes the subject line is fully redundant, and sometimes it includes important information
    if simple_subject in body:
        # If the body repeats the simplified-subject, only return the body
        return body
    else:
        # If the body does not start with the subject, combine the two
        return mail.subject + '\n\n' + body


def create_thread(username, password, text, max_len=300):
    client = Client()
    client.login(username, password)

    posts = split_to_posts(text, max_len=max_len)
    # Note: Root is 1st post in thread, parent is post we're replying to
    parent_ref = None
    root_ref = None
    for post in posts:
        log.debug(f"Sending post as {username} in response to {parent_ref}: {post}")
        parent_ref = send_post_with_hyperlinks(client, post, root_ref, parent_ref)
        if not root_ref:
            # if we don't have a root yet, this is the root
            root_ref = parent_ref


def split_to_posts(text:str, max_len=300) -> list[str]:
    """Splits text into 300-character posts. Attempts to split on newlines to avoid interrupting sentences."""
    lines = text.splitlines()
    posts = []
    curline = lines[0]
    for line in lines[1:]:
        if len(curline) + len(line) + 1 <= max_len:
            curline += "\n"
            curline += line
        else:
            posts.append(curline)
            if len(line) <= max_len:
                curline = line
            else:
                # We've got one line that is longer than 300 characters; split it at word boundaries
                words = text.split()
                curline = words[0]
                for word in words[1:]:
                    if len(curline) + len(word) + 1 <= max_len:
                        curline += " "
                        curline += word
                    else:
                        posts.append(curline)
                        curline = word
    posts.append(curline)
    return posts


def send_post_with_hyperlinks(client: Client, text: str, root_ref=None, parent_ref=None) \
        -> models.ComAtprotoRepoStrongRef.Main:
    url_positions = extract_url_byte_positions(text)
    facets = []
    for uri, byte_start, byte_end in url_positions:
        facets.append(models.AppBskyRichtextFacet.Main(
            features=[models.AppBskyRichtextFacet.Link(uri=uri)],
            index=models.AppBskyRichtextFacet.ByteSlice(byte_start=byte_start, byte_end=byte_end)
        ))

    if parent_ref and root_ref:
        reply_ref = models.AppBskyFeedPost.ReplyRef(parent=parent_ref, root=root_ref)
    else:
        reply_ref = None

    return models.create_strong_ref(client.send_post(text, facets=facets, reply_to=reply_ref))


def extract_url_byte_positions(text: str, *, encoding: str = 'UTF-8') -> t.List[t.Tuple[str, int, int]]:
    """This function will detect any links beginning with http or https."""
    encoded_text = text.encode(encoding)

    # Adjusted URL matching pattern
    pattern = rb'https?://[^ \n\r\t]*'

    matches = re.finditer(pattern, encoded_text)
    url_byte_positions = []

    for match in matches:
        url_bytes = match.group(0)
        url = url_bytes.decode(encoding)
        url_byte_positions.append((url, match.start(), match.end()))

    return url_byte_positions


def deep_get(d, *keys):
    _d = d
    for key in keys:
        if isinstance(key, int) or key in _d:
            _d = _d[key]
        else:
            return None
    return _d


if __name__ == "__main__":
    with open("test_event.json") as test_file:
        event = json.load(test_file)
        lambda_handler(event, None)