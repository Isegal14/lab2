import os
import sqlite3
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")

db = sqlite3.connect(":memory:", check_same_thread=False)
sessions = {}
next_token = 1000


def create_data():
    # таблицы и тестовые данные
    db.execute("CREATE TABLE users (username TEXT, password TEXT)")
    db.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, text TEXT)")
    db.execute("INSERT INTO users VALUES ('admin', 'adminpass')")
    db.execute("INSERT INTO users VALUES ('alice', 'alice123')")
    db.execute("INSERT INTO users VALUES ('bob', 'bob456')")
    db.execute("INSERT INTO notes (owner, title, text) VALUES ('admin', 'Доступ к серверу', 'root password: Sup3rS3cret!')")
    db.execute("INSERT INTO notes (owner, title, text) VALUES ('alice', 'Покупки', 'молоко, хлеб, сыр')")
    db.execute("INSERT INTO notes (owner, title, text) VALUES ('bob', 'Личное', 'PIN от карты: 4921')")
    db.execute("INSERT INTO notes (owner, title, text) VALUES ('alice', 'Идеи', 'сделать лабораторную')")
    db.commit()
    os.makedirs(FILES_DIR, exist_ok=True)
    open(os.path.join(FILES_DIR, "readme.txt"), "w").write("Публичный файл\n")
    open(os.path.join(FILES_DIR, "report.txt"), "w").write("Публичный отчёт\n")
    # секретный файл лежит рядом с приложением, а не в папке files
    open(os.path.join(BASE_DIR, "config.ini"), "w").write(
        "SECRET_KEY = lab-demo-secret-key-123\nDB_PASSWORD = lab-demo-db-pass\n")


def make_page(body, user):
    if user:
        who = "Вы вошли как: " + escape(user)
    else:
        who = "Вы не авторизованы"
    return ("<html><head><meta charset='utf-8'></head><body><h1>NoteBox</h1><p>" + who + "</p>"
            "<a href='/login'>Вход</a> | <a href='/notes'>Мои заметки</a> | <a href='/files'>Файлы</a>"
            "<hr>" + body + "</body></html>")


LOGIN_FORM = ("<form method='post' action='/login'>"
              "<input name='username'><input name='password' type='password'>"
              "<button>Войти</button></form>")


class Handler(BaseHTTPRequestHandler):

    def get_user(self):
        # ищем в cookie токен сессии и возвращаем имя пользователя
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "session":
                return sessions.get(value)
        return None

    def answer(self, body, code=200, cookie=None, plain=False):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        if plain:
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        else:
            self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        params = parse_qs(url.query)
        user = self.get_user()

        if url.path == "/":
            self.answer(make_page("Личные заметки и файлы", user))

        elif url.path == "/login":
            self.answer(make_page(LOGIN_FORM, user))

        elif url.path == "/notes":
            if user is None:
                self.answer(make_page("Нужен вход", None), 401)
                return
            rows = db.execute("SELECT id, title FROM notes WHERE owner = ?", (user,)).fetchall()
            body = "<ul>"
            for note_id, title in rows:
                body += "<li><a href='/note?id=" + str(note_id) + "'>" + escape(title) + "</a></li>"
            body += "</ul>"
            self.answer(make_page(body, user))

        elif url.path == "/note":
            if user is None:
                self.answer(make_page("Нужен вход", None), 401)
                return
            note_id = params.get("id", ["0"])[0]
            row = db.execute("SELECT owner, title, text FROM notes WHERE id = ?", (note_id,)).fetchone()
            if row is None:
                self.answer(make_page("Заметка не найдена", user), 404)
                return
            owner, title, text = row
            # УЯЗВИМОСТЬ 1 (IDOR): не проверяем, что заметка принадлежит user
            body = "<h2>" + escape(title) + "</h2><p>Автор: " + escape(owner) + "</p><pre>" + escape(text) + "</pre>"
            self.answer(make_page(body, user))

        elif url.path == "/files":
            body = "<ul>"
            for name in os.listdir(FILES_DIR):
                body += "<li><a href='/download?name=" + name + "'>" + name + "</a></li>"
            body += "</ul>"
            self.answer(make_page(body, user))

        elif url.path == "/download":
            name = params.get("name", [""])[0]
            # УЯЗВИМОСТЬ 2 (Path Traversal): имя файла не проверяется, можно написать ../
            path = os.path.join(FILES_DIR, name)
            if os.path.isfile(path):
                self.answer(open(path, "rb").read(), plain=True)
            else:
                self.answer(make_page("Файл не найден", user), 404)

        else:
            self.answer(make_page("404", user), 404)

    def do_POST(self):
        global next_token
        if self.path != "/login":
            self.answer(make_page("404", None), 404)
            return

        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode())
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]

        row = db.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                         (username, password)).fetchone()
        if row is None:
            self.answer(make_page("Неверный логин или пароль" + LOGIN_FORM, None), 401)
            return

        # УЯЗВИМОСТЬ 3: токен - просто следующее число (1000, 1001, ...), его легко угадать
        token = str(next_token)
        next_token = next_token + 1
        sessions[token] = username
        self.answer(make_page("Добро пожаловать, " + escape(username), username),
                    cookie="session=" + token + "; Path=/")

    def log_message(self, *args):
        pass  # не печатаем лог запросов


create_data()
sessions["1000"] = "admin"
next_token = 1001

if __name__ == "__main__":
    print("Сервер запущен: http://127.0.0.1:8001")
    HTTPServer(("127.0.0.1", 8001), Handler).serve_forever()
