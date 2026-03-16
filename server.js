const express = require("express");
const mysql = require("mysql2/promise");
const path = require("path");
const cookieParser = require("cookie-parser");
const crypto = require("crypto"); // встроенный модуль для хеширования и подписи
const app = express();
const port = 8888; // или другой порт

// Секретный ключ для подписи JWT (храните в безопасности, например в переменных окружения)
const JWT_SECRET = "my_super_secret_key_change_it";

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Настройки БД
const dbConfig = {
  host: "localhost",
  user: "u82413",
  password: "2483755",
  database: "u82413",
};

// ==================== Вспомогательные функции ====================

// Хеширование пароля с солью (используем pbkdf2)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .pbkdf2Sync(password, salt, 1000, 64, "sha512")
    .toString("hex");
  return `${salt}:${hash}`;
}

// Проверка пароля
function verifyPassword(password, storedHash) {
  const [salt, hash] = storedHash.split(":");
  const verifyHash = crypto
    .pbkdf2Sync(password, salt, 1000, 64, "sha512")
    .toString("hex");
  return hash === verifyHash;
}

// Генерация случайного пароля (8 символов)
function generatePassword() {
  return crypto.randomBytes(4).toString("hex"); // 8 символов в hex
}

// Создание JWT-подобного токена (payload + подпись)
function createToken(payload, expiresIn = "1d") {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 24 * 60 * 60; // 1 день
  const fullPayload = { ...payload, exp, iat: now };
  const base64Header = Buffer.from(JSON.stringify(header)).toString(
    "base64url",
  );
  const base64Payload = Buffer.from(JSON.stringify(fullPayload)).toString(
    "base64url",
  );
  const signature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(`${base64Header}.${base64Payload}`)
    .digest("base64url");
  return `${base64Header}.${base64Payload}.${signature}`;
}

// Проверка и декодирование токена
function verifyToken(token) {
  try {
    const [headerB64, payloadB64, signatureB64] = token.split(".");
    const signature = crypto
      .createHmac("sha256", JWT_SECRET)
      .update(`${headerB64}.${payloadB64}`)
      .digest("base64url");
    if (signature !== signatureB64) return null;
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) return null; // просрочен
    return payload;
  } catch {
    return null;
  }
}

// Middleware для проверки аутентификации
async function authMiddleware(req, res, next) {
  const token = req.cookies.authToken;
  if (!token) return res.redirect("/login?error=Требуется вход");
  const payload = verifyToken(token);
  if (!payload) {
    res.clearCookie("authToken");
    return res.redirect("/login?error=Сессия истекла");
  }
  req.submissionId = payload.sub; // ID записи из токена
  next();
}

// ==================== Валидационные функции (из 4-й лабы) ====================
// (полностью скопировать из предыдущего server.js)
function validateFullName(name) {
  if (!name || name.trim() === "") return "ФИО не может быть пустым";
  if (name.length > 150) return "ФИО не должно превышать 150 символов";
  if (!/^[a-zA-Zа-яА-ЯёЁ\s-]+$/u.test(name)) {
    return "ФИО должно содержать только буквы, пробелы и дефисы";
  }
  return null;
}

function validatePhone(phone) {
  if (!phone) return "Телефон не может быть пустым";
  if (!/^[\d\s+()-]{5,20}$/.test(phone)) {
    return "Телефон может содержать только цифры, пробелы, +, -, (, ) (от 5 до 20 символов)";
  }
  return null;
}

function validateEmail(email) {
  if (!email) return "Email не может быть пустым";
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!re.test(email))
    return "Введите корректный email (например, name@domain.ru)";
  return null;
}

function validateBirthDate(dateStr) {
  if (!dateStr) return "Дата рождения не может быть пустой";
  const date = new Date(dateStr);
  if (isNaN(date.getTime()))
    return "Некорректная дата. Используйте формат ГГГГ-ММ-ДД";
  if (date > new Date()) return "Дата не может быть в будущем";
  return null;
}

function validateGender(gender) {
  const allowed = ["male", "female"];
  if (!gender || !allowed.includes(gender)) {
    return "Выберите пол: Мужской или Женский";
  }
  return null;
}

function validateLanguages(langs) {
  const allowed = [
    "Pascal",
    "C",
    "C++",
    "JavaScript",
    "PHP",
    "Python",
    "Java",
    "Haskel",
    "Clojure",
    "Prolog",
    "Scala",
    "Go",
  ];
  if (!langs || langs.length === 0) return "Выберите хотя бы один язык";
  const languages = Array.isArray(langs) ? langs : [langs];
  for (let lang of languages) {
    if (!allowed.includes(lang)) {
      return `Язык "${lang}" недопустим. Допустимые языки: ${allowed.join(", ")}`;
    }
  }
  return null;
}

function validateBiography(bio) {
  if (bio && bio.length > 5000)
    return "Биография не должна превышать 5000 символов";
  return null;
}

function validateContract(contract) {
  if (!contract || (contract !== "on" && contract !== "1")) {
    return "Необходимо отметить, что вы ознакомлены с контрактом";
  }
  return null;
}

// ==================== Функции генерации HTML ====================

function renderForm(
  data = {},
  errors = {},
  successMessage = null,
  isEdit = false,
) {
  const fullName = data.full_name || "";
  const phone = data.phone || "";
  const email = data.email || "";
  const birthDate = data.birth_date || "";
  const gender = data.gender || "";
  const biography = data.biography || "";
  const contract =
    data.contract === "on" || data.contract === "1" || data.contract === true;

  let selectedLangs = data.languages || [];
  if (!Array.isArray(selectedLangs)) selectedLangs = [selectedLangs];

  const allLangs = [
    "Pascal",
    "C",
    "C++",
    "JavaScript",
    "PHP",
    "Python",
    "Java",
    "Haskel",
    "Clojure",
    "Prolog",
    "Scala",
    "Go",
  ];

  const labNotice =
    '<div style="background: #ffd700; padding: 10px; text-align: center; font-weight: bold; border-radius: 5px; margin-bottom: 20px;">Лабораторная работа №5 (аутентификация для редактирования)</div>';

  let html = `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Анкета (lab5)</title>
    <link rel="stylesheet" href="style.css">
    <style>
        .error-message { color: red; font-size: 0.9em; margin-top: 5px; }
        .error-input { border: 2px solid red !important; background-color: #ffe6e6; }
        .success-message { background: #d4edda; color: #155724; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .credentials { background: #e2f0ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="form-card">
        ${labNotice}`;

  if (successMessage) {
    html += `<div class="success-message">${successMessage}</div>`;
  }

  if (Object.keys(errors).length > 0) {
    html += '<div class="error-list"><ul>';
    for (let field in errors) {
      html += `<li>${errors[field]}</li>`;
    }
    html += "</ul></div>";
  }

  const action = isEdit ? "/edit" : "/";
  html += `<form method="POST" action="${action}">
            <label for="full_name">ФИО:</label>
            <input type="text" id="full_name" name="full_name" value="${fullName}" class="${errors.full_name ? "error-input" : ""}" required>
            ${errors.full_name ? `<div class="error-message">${errors.full_name}</div>` : ""}

            <label for="phone">Телефон:</label>
            <input type="tel" id="phone" name="phone" value="${phone}" class="${errors.phone ? "error-input" : ""}" required>
            ${errors.phone ? `<div class="error-message">${errors.phone}</div>` : ""}

            <label for="email">E-mail:</label>
            <input type="email" id="email" name="email" value="${email}" class="${errors.email ? "error-input" : ""}" required>
            ${errors.email ? `<div class="error-message">${errors.email}</div>` : ""}

            <label for="birth_date">Дата рождения:</label>
            <input type="date" id="birth_date" name="birth_date" value="${birthDate}" class="${errors.birth_date ? "error-input" : ""}" required>
            ${errors.birth_date ? `<div class="error-message">${errors.birth_date}</div>` : ""}

            <label>Пол:</label>
            <div class="radio-group">
                <label><input type="radio" name="gender" value="male" ${gender === "male" ? "checked" : ""} required> Мужской</label>
                <label><input type="radio" name="gender" value="female" ${gender === "female" ? "checked" : ""} required> Женский</label>
            </div>
            ${errors.gender ? `<div class="error-message">${errors.gender}</div>` : ""}

            <label>Любимые языки программирования:</label>
            <div class="checkbox-group">`;

  allLangs.forEach((lang) => {
    const checked = selectedLangs.includes(lang) ? "checked" : "";
    html += `<label><input type="checkbox" name="languages[]" value="${lang}" ${checked}> ${lang}</label>`;
  });

  html += `</div>
            ${errors.languages ? `<div class="error-message">${errors.languages}</div>` : ""}

            <label for="biography">Биография:</label>
            <textarea id="biography" name="biography" rows="5" class="${errors.biography ? "error-input" : ""}">${biography}</textarea>
            ${errors.biography ? `<div class="error-message">${errors.biography}</div>` : ""}

            <div class="contract">
                <input type="checkbox" id="contract" name="contract" value="1" ${contract ? "checked" : ""} required>
                <label for="contract">С контрактом ознакомлен(а)</label>
            </div>
            ${errors.contract ? `<div class="error-message">${errors.contract}</div>` : ""}

            <button type="submit">${isEdit ? "Обновить" : "Сохранить"}</button>
        </form>`;

  // Если есть данные об учётной записи, показываем их
  if (data.login && data.password) {
    html += `<div class="credentials">
            <strong>Ваши учётные данные для редактирования:</strong><br>
            Логин: ${data.login}<br>
            Пароль: ${data.password}<br>
            <em>Сохраните их! Они понадобятся для входа.</em>
        </div>`;
  }

  // Ссылка на вход, если не на странице логина
  if (!isEdit && !reqPath) {
    html += `<p style="text-align: center; margin-top: 20px;"><a href="/login">Войти для редактирования</a></p>`;
  }

  html += "</div></body></html>";
  return html;
}

function renderLogin(error = "") {
  const labNotice =
    '<div style="background: #ffd700; padding: 10px; text-align: center; font-weight: bold; border-radius: 5px; margin-bottom: 20px;">Лабораторная работа №5 (вход)</div>';
  return `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Вход</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="form-card">
        ${labNotice}
        <h1>Вход для редактирования</h1>
        ${error ? `<div class="error-message">${error}</div>` : ""}
        <form method="POST" action="/login">
            <label for="login">Логин:</label>
            <input type="text" id="login" name="login" required>
            <label for="password">Пароль:</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Войти</button>
        </form>
        <p style="text-align: center; margin-top: 20px;"><a href="/">Вернуться к анкете</a></p>
    </div>
</body>
</html>`;
}

// ==================== Маршруты ====================

// Главная страница (форма отправки)
app.get("/", (req, res) => {
  let data = {};
  let errors = {};
  let successMessage = null;

  if (req.cookies.formData) {
    try {
      data = JSON.parse(req.cookies.formData);
    } catch {}
  }
  if (req.cookies.formErrors) {
    try {
      errors = JSON.parse(req.cookies.formErrors);
      res.clearCookie("formErrors");
    } catch {}
  }
  if (req.cookies.successMessage) {
    successMessage = req.cookies.successMessage;
    res.clearCookie("successMessage");
  }

  res.send(renderForm(data, errors, successMessage, false));
});

// Обработка отправки новой формы (без логина)
app.post("/", async (req, res) => {
  const data = req.body;
  const errors = {};

  // Валидация (такая же)
  const nameErr = validateFullName(data.full_name);
  if (nameErr) errors.full_name = nameErr;
  const phoneErr = validatePhone(data.phone);
  if (phoneErr) errors.phone = phoneErr;
  const emailErr = validateEmail(data.email);
  if (emailErr) errors.email = emailErr;
  const birthErr = validateBirthDate(data.birth_date);
  if (birthErr) errors.birth_date = birthErr;
  const genderErr = validateGender(data.gender);
  if (genderErr) errors.gender = genderErr;
  const langErr = validateLanguages(data.languages);
  if (langErr) errors.languages = langErr;
  const bioErr = validateBiography(data.biography);
  if (bioErr) errors.biography = bioErr;
  const contractErr = validateContract(data.contract);
  if (contractErr) errors.contract = contractErr;

  if (Object.keys(errors).length > 0) {
    res.cookie("formData", JSON.stringify(data), { maxAge: 3600000 });
    res.cookie("formErrors", JSON.stringify(errors), { maxAge: 3600000 });
    return res.redirect("/");
  }

  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    await connection.beginTransaction();

    // Вставка основной записи
    const [result] = await connection.execute(
      `INSERT INTO submissions (full_name, phone, email, birth_date, gender, biography, contract_accepted)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        data.full_name,
        data.phone,
        data.email,
        data.birth_date,
        data.gender,
        data.biography || null,
        data.contract ? 1 : 0,
      ],
    );
    const submissionId = result.insertId;

    // Языки
    const languages = Array.isArray(data.languages)
      ? data.languages
      : [data.languages];
    for (let lang of languages) {
      await connection.execute(
        "INSERT INTO submission_languages (submission_id, language) VALUES (?, ?)",
        [submissionId, lang],
      );
    }

    // Генерация логина и пароля
    const login = `user_${submissionId}`;
    const password = generatePassword();
    const passwordHash = hashPassword(password);

    // Обновление записи с логином и хешем
    await connection.execute(
      "UPDATE submissions SET login = ?, password_hash = ? WHERE id = ?",
      [login, passwordHash, submissionId],
    );

    await connection.commit();

    // Сохраняем данные в куку для предзаполнения, но добавляем логин и пароль для отображения
    const responseData = { ...data, login, password };
    res.cookie("formData", JSON.stringify(responseData), {
      maxAge: 365 * 24 * 60 * 60 * 1000,
    });
    res.cookie(
      "successMessage",
      "Данные сохранены! Запишите логин и пароль для редактирования.",
      { maxAge: 5000 },
    );
    res.clearCookie("formErrors");
    res.redirect("/");
  } catch (err) {
    if (connection) await connection.rollback();
    console.error(err);
    errors.database = "Ошибка базы данных, попробуйте позже.";
    res.cookie("formData", JSON.stringify(data), { maxAge: 3600000 });
    res.cookie("formErrors", JSON.stringify(errors), { maxAge: 3600000 });
    res.redirect("/");
  } finally {
    if (connection) await connection.end();
  }
});

// Страница входа
app.get("/login", (req, res) => {
  const error = req.query.error || "";
  res.send(renderLogin(error));
});

// Обработка входа
app.post("/login", async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) {
    return res.redirect("/login?error=Заполните все поля");
  }

  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      "SELECT id, password_hash FROM submissions WHERE login = ?",
      [login],
    );
    if (rows.length === 0) {
      return res.redirect("/login?error=Неверный логин или пароль");
    }
    const user = rows[0];
    if (!verifyPassword(password, user.password_hash)) {
      return res.redirect("/login?error=Неверный логин или пароль");
    }

    // Создаём токен
    const token = createToken({ sub: user.id });
    res.cookie("authToken", token, {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
    });
    res.redirect("/edit");
  } catch (err) {
    console.error(err);
    res.redirect("/login?error=Ошибка сервера");
  } finally {
    if (connection) await connection.end();
  }
});

// Страница редактирования (только для аутентифицированных)
app.get("/edit", authMiddleware, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      "SELECT full_name, phone, email, birth_date, gender, biography FROM submissions WHERE id = ?",
      [req.submissionId],
    );
    if (rows.length === 0) return res.redirect("/");
    const data = rows[0];
    // Загружаем языки
    const [langRows] = await connection.execute(
      "SELECT language FROM submission_languages WHERE submission_id = ?",
      [req.submissionId],
    );
    data.languages = langRows.map((r) => r.language);
    // Отображаем форму редактирования
    res.send(renderForm(data, {}, null, true));
  } catch (err) {
    console.error(err);
    res.redirect("/");
  } finally {
    if (connection) await connection.end();
  }
});

// Обработка обновления данных
app.post("/edit", authMiddleware, async (req, res) => {
  const data = req.body;
  const errors = {};

  // Валидация (такая же)
  const nameErr = validateFullName(data.full_name);
  if (nameErr) errors.full_name = nameErr;
  const phoneErr = validatePhone(data.phone);
  if (phoneErr) errors.phone = phoneErr;
  const emailErr = validateEmail(data.email);
  if (emailErr) errors.email = emailErr;
  const birthErr = validateBirthDate(data.birth_date);
  if (birthErr) errors.birth_date = birthErr;
  const genderErr = validateGender(data.gender);
  if (genderErr) errors.gender = genderErr;
  const langErr = validateLanguages(data.languages);
  if (langErr) errors.languages = langErr;
  const bioErr = validateBiography(data.biography);
  if (bioErr) errors.biography = bioErr;
  const contractErr = validateContract(data.contract);
  if (contractErr) errors.contract = contractErr;

  if (Object.keys(errors).length > 0) {
    // При ошибках показываем форму редактирования с ошибками
    res.send(renderForm(data, errors, null, true));
    return;
  }

  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    await connection.beginTransaction();

    // Обновляем основную запись
    await connection.execute(
      `UPDATE submissions SET full_name = ?, phone = ?, email = ?, birth_date = ?, gender = ?, biography = ?, contract_accepted = ?
             WHERE id = ?`,
      [
        data.full_name,
        data.phone,
        data.email,
        data.birth_date,
        data.gender,
        data.biography || null,
        data.contract ? 1 : 0,
        req.submissionId,
      ],
    );

    // Удаляем старые языки и вставляем новые
    await connection.execute(
      "DELETE FROM submission_languages WHERE submission_id = ?",
      [req.submissionId],
    );
    const languages = Array.isArray(data.languages)
      ? data.languages
      : [data.languages];
    for (let lang of languages) {
      await connection.execute(
        "INSERT INTO submission_languages (submission_id, language) VALUES (?, ?)",
        [req.submissionId, lang],
      );
    }

    await connection.commit();

    // Перенаправляем на страницу редактирования с сообщением об успехе
    res.cookie("successMessage", "Данные успешно обновлены", { maxAge: 5000 });
    res.redirect("/edit");
  } catch (err) {
    if (connection) await connection.rollback();
    console.error(err);
    errors.database = "Ошибка базы данных, попробуйте позже.";
    res.send(renderForm(data, errors, null, true));
  } finally {
    if (connection) await connection.end();
  }
});

// Выход
app.get("/logout", (req, res) => {
  res.clearCookie("authToken");
  res.redirect("/");
});

// Статика
app.use(express.static(path.join(__dirname, "public")));

app.listen(port, () => {
  console.log(`Сервер запущен на http://localhost:${port}`);
});
