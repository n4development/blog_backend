import os
import jinja2
import webapp2
import re
import hmac
import random
from string import letters
import hashlib
from google.appengine.ext import db


teplate_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(teplate_dir),
                               autoescape=True)
secret = '4d8ed0785179d3b37ff4d6f7c2e234db'


def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def make_secure_val(val):
    # generate a hash
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# Blog Model


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    created_by = db.StringProperty(required=True)

    @classmethod
    def by_id(cls, pid):
        key = db.Key.from_path('Post', int(pid))
        return db.get(key)

    @classmethod
    def by_creator(cls, cid):
        return Post.all().filter('created_by =', cid).get()

    @classmethod
    def is_editable(cls, cid, pid):
        post = Post.by_id(pid)
        return post and post.created_by == cid

# User Model


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class MainPage(Handler):

    def get(self):
        posts = Post.all().order('-created')
        self.render('blog_list.html', posts=posts)


class NewPost(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(subject=subject, content=content, created_by=self.read_secure_cookie('user_id'))
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class Register(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if self.email and not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class PostPage(Handler):
    def get(self, post_id):
        post = Post.by_id(post_id)
        edit_able = Post.is_editable(self.read_secure_cookie('user_id'), post_id)
        print ">>>>>"+str(edit_able)
        if not post:
            self.error(404)
            return

        self.render("single_post.html", post=post, editable=edit_able)


class PostEditPage(Handler):

    def get(self, post_id):
        post = Post.by_id(post_id)
        edit_able = Post.is_editable(self.read_secure_cookie('user_id'), post_id)
        if not post or not edit_able:
            self.error(404)
            return

        self.render("edit_post.html", subject=post.subject, content=post.content)

    def post(self, post_id):

        post = Post.by_id(post_id)
        edit_able = Post.is_editable(self.read_secure_cookie('user_id'), post_id)
        if not post or not edit_able:
            self.redirect('/blog')
            return

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("edit_post.html", subject=subject, content=content, error=error)


class PostDelete(Handler):

    def get(self, post_id):
        post = Post.by_id(post_id)
        edit_able = Post.is_editable(self.read_secure_cookie('user_id'), post_id)
        if not post or not edit_able:
            self.error(404)
            return

        self.render("post_delete.html", post=post)

    def post(self, post_id):

        post = Post.by_id(post_id)
        edit_able = Post.is_editable(self.read_secure_cookie('user_id'), post_id)
        if not post or not edit_able:
            self.redirect('/blog')
            return

        post.delete()
        self.redirect('/')


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', MainPage),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/edit/([0-9]+)', PostEditPage),
                               ('/blog/delete/([0-9]+)', PostDelete),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)




def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username)


def valid_password(password):
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    return PASSWORD_RE.match(password)


def valid_email(email):
    EMAIl_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return EMAIl_RE.match(email)
