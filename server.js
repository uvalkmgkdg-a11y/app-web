const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-me';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new Database('attendance.db');

function initDb() {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT CHECK(role IN ('student','professor')) NOT NULL
    );
  `).run();

  db.prepare(`
    CREATE TABLE IF NOT EXISTS courses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      code TEXT UNIQUE NOT NULL,
      professor_id INTEGER NOT NULL,
      FOREIGN KEY(professor_id) REFERENCES users(id)
    );
  `).run();

  db.prepare(`
    CREATE TABLE IF NOT EXISTS enrollments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_id INTEGER NOT NULL,
      course_id INTEGER NOT NULL,
      UNIQUE(student_id, course_id),
      FOREIGN KEY(student_id) REFERENCES users(id),
      FOREIGN KEY(course_id) REFERENCES courses(id)
    );
  `).run();

  db.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      course_id INTEGER NOT NULL,
      session_date TEXT NOT NULL,
      session_code TEXT UNIQUE NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(course_id) REFERENCES courses(id)
    );
  `).run();

  db.prepare(`
    CREATE TABLE IF NOT EXISTS attendance (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id INTEGER NOT NULL,
      student_id INTEGER NOT NULL,
      timestamp TEXT DEFAULT (datetime('now')),
      UNIQUE(session_id, student_id),
      FOREIGN KEY(session_id) REFERENCES sessions(id),
      FOREIGN KEY(student_id) REFERENCES users(id)
    );
  `).run();
}

function seedData() {
  const userCount = db.prepare('SELECT COUNT(*) AS count FROM users').get();
  if (userCount.count > 0) {
    return;
  }

  const password = '123456';
  const hash = bcrypt.hashSync(password, 10);

  const insertUser = db.prepare(`
    INSERT INTO users (username, display_name, password_hash, role)
    VALUES (?, ?, ?, ?)
  `);

  const profAhmed = insertUser.run('prof_ahmed', 'د. أحمد', hash, 'professor').lastInsertRowid;
  const profMona = insertUser.run('prof_mona', 'د. منى', hash, 'professor').lastInsertRowid;
  const studentSara = insertUser.run('student_sara', 'سارة محمد', hash, 'student').lastInsertRowid;
  const studentOmar = insertUser.run('student_omar', 'عمر علي', hash, 'student').lastInsertRowid;

  const insertCourse = db.prepare(`
    INSERT INTO courses (name, code, professor_id)
    VALUES (?, ?, ?)
  `);

  const cs101 = insertCourse.run('مقدمة في البرمجة', 'CS101', profAhmed).lastInsertRowid;
  const cs205 = insertCourse.run('هياكل بيانات', 'CS205', profAhmed).lastInsertRowid;
  const math110 = insertCourse.run('رياضة هندسية', 'MATH110', profMona).lastInsertRowid;

  const insertEnrollment = db.prepare(`
    INSERT INTO enrollments (student_id, course_id)
    VALUES (?, ?)
  `);

  insertEnrollment.run(studentSara, cs101);
  insertEnrollment.run(studentSara, cs205);
  insertEnrollment.run(studentOmar, cs101);
  insertEnrollment.run(studentOmar, math110);
}

initDb();
seedData();

function auth(requiredRole) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'محتاج تسجل دخول الأول' });
    }
    const token = authHeader.replace('Bearer ', '').trim();
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (requiredRole && payload.role !== requiredRole) {
        return res.status(403).json({ error: 'معندكش صلاحيات تكمل هنا' });
      }
      req.user = payload;
      next();
    } catch (err) {
      return res.status(401).json({ error: 'الجلسة انتهت أو فيها مشكلة، سجل دخول تاني' });
    }
  };
}

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'دخل اسم المستخدم والباسورد' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) {
    return res.status(401).json({ error: 'البيانات مش صحيحة' });
  }

  const isMatch = bcrypt.compareSync(password, user.password_hash);
  if (!isMatch) {
    return res.status(401).json({ error: 'البيانات مش صحيحة' });
  }

  const token = jwt.sign(
    {
      id: user.id,
      role: user.role,
      displayName: user.display_name
    },
    JWT_SECRET,
    { expiresIn: '12h' }
  );

  return res.json({
    token,
    role: user.role,
    displayName: user.display_name,
    username: user.username
  });
});

app.get('/api/student/courses', auth('student'), (req, res) => {
  const courses = db.prepare(`
    SELECT c.id, c.name, c.code
    FROM courses c
    INNER JOIN enrollments e ON e.course_id = c.id
    WHERE e.student_id = ?
    ORDER BY c.name
  `).all(req.user.id);
  res.json(courses);
});

app.get('/api/student/history', auth('student'), (req, res) => {
  const history = db.prepare(`
    SELECT c.name AS courseName,
           s.session_date AS sessionDate,
           a.timestamp AS scannedAt,
           s.session_code AS sessionCode
    FROM attendance a
    INNER JOIN sessions s ON s.id = a.session_id
    INNER JOIN courses c ON c.id = s.course_id
    WHERE a.student_id = ?
    ORDER BY s.session_date DESC, a.timestamp DESC
  `).all(req.user.id);
  res.json(history);
});

app.post('/api/student/attendance', auth('student'), (req, res) => {
  const { sessionCode } = req.body || {};
  if (!sessionCode) {
    return res.status(400).json({ error: 'لازم كود الجلسة' });
  }

  const session = db.prepare(`
    SELECT s.id, s.course_id, c.name AS courseName
    FROM sessions s
    INNER JOIN courses c ON c.id = s.course_id
    WHERE s.session_code = ?
  `).get(sessionCode.trim());

  if (!session) {
    return res.status(404).json({ error: 'الكود ده مش موجود' });
  }

  const isEnrolled = db.prepare(`
    SELECT 1 FROM enrollments WHERE student_id = ? AND course_id = ?
  `).get(req.user.id, session.course_id);

  if (!isEnrolled) {
    return res.status(403).json({ error: 'مش مسجل في المادة دي' });
  }

  const alreadySigned = db.prepare(`
    SELECT 1 FROM attendance WHERE session_id = ? AND student_id = ?
  `).get(session.id, req.user.id);

  if (alreadySigned) {
    return res.json({ message: 'الحضور متسجل لك قبل كده 👍' });
  }

  db.prepare(`
    INSERT INTO attendance (session_id, student_id) VALUES (?, ?)
  `).run(session.id, req.user.id);

  return res.json({
    message: 'تم تسجيل حضورك بنجاح 🎉',
    courseName: session.courseName
  });
});

app.get('/api/prof/courses', auth('professor'), (req, res) => {
  const courses = db.prepare(`
    SELECT id, name, code
    FROM courses
    WHERE professor_id = ?
    ORDER BY name
  `).all(req.user.id);
  res.json(courses);
});

app.post('/api/prof/sessions', auth('professor'), (req, res) => {
  const { courseId, sessionDate } = req.body || {};
  if (!courseId || !sessionDate) {
    return res.status(400).json({ error: 'اختر الكورس وحدد التاريخ' });
  }

  const course = db.prepare(`
    SELECT id, code, professor_id FROM courses WHERE id = ?
  `).get(courseId);

  if (!course) {
    return res.status(404).json({ error: 'الكورس مش موجود' });
  }

  if (course.professor_id !== req.user.id) {
    return res.status(403).json({ error: 'الكورس ده مش تبعك' });
  }

  const parsedDate = new Date(sessionDate);
  if (Number.isNaN(parsedDate.getTime())) {
    return res.status(400).json({ error: 'التاريخ مش مظبوط' });
  }
  const isoDate = parsedDate.toISOString().slice(0, 10);
  let sessionCode;
  let exists = true;

  const checkSessionCode = db.prepare(`
    SELECT 1 FROM sessions WHERE session_code = ?
  `);

  do {
    const randomPart = Math.random().toString(36).slice(2, 7).toUpperCase();
    sessionCode = `${course.code}-${isoDate.replace(/-/g, '')}-${randomPart}`;
    exists = checkSessionCode.get(sessionCode);
  } while (exists);

  const info = db.prepare(`
    INSERT INTO sessions (course_id, session_date, session_code)
    VALUES (?, ?, ?)
  `).run(course.id, isoDate, sessionCode);

  return res.json({
    sessionId: info.lastInsertRowid,
    sessionCode,
    sessionDate: isoDate
  });
});

app.get('/api/prof/sessions/:courseId', auth('professor'), (req, res) => {
  const courseId = Number(req.params.courseId);
  if (!courseId) {
    return res.status(400).json({ error: 'كود كورس مش صحيح' });
  }

  const course = db.prepare(`
    SELECT id, professor_id FROM courses WHERE id = ?
  `).get(courseId);

  if (!course) {
    return res.status(404).json({ error: 'الكورس مش موجود' });
  }

  if (course.professor_id !== req.user.id) {
    return res.status(403).json({ error: 'مالكيش صلاحية للكورس ده' });
  }

  const sessions = db.prepare(`
    SELECT s.id,
           s.session_date AS sessionDate,
           s.session_code AS sessionCode,
           COUNT(a.id) AS attendanceCount
    FROM sessions s
    LEFT JOIN attendance a ON a.session_id = s.id
    WHERE s.course_id = ?
    GROUP BY s.id
    ORDER BY s.session_date DESC, s.id DESC
  `).all(courseId);

  res.json(sessions);
});

app.get('/api/prof/sessions/:sessionId/attendance', auth('professor'), (req, res) => {
  const sessionId = Number(req.params.sessionId);
  if (!sessionId) {
    return res.status(400).json({ error: 'كود جلسة مش صحيح' });
  }

  const session = db.prepare(`
    SELECT s.id, s.session_date, s.course_id, c.professor_id, c.name AS courseName
    FROM sessions s
    INNER JOIN courses c ON c.id = s.course_id
    WHERE s.id = ?
  `).get(sessionId);

  if (!session) {
    return res.status(404).json({ error: 'الجلسة مش موجودة' });
  }

  if (session.professor_id !== req.user.id) {
    return res.status(403).json({ error: 'مش من حقك تشوف الحضور هنا' });
  }

  const attendees = db.prepare(`
    SELECT u.display_name AS studentName,
           u.username,
           a.timestamp AS attendedAt
    FROM attendance a
    INNER JOIN users u ON u.id = a.student_id
    WHERE a.session_id = ?
    ORDER BY a.timestamp ASC
  `).all(sessionId);

  res.json({
    sessionDate: session.session_date,
    courseName: session.courseName,
    attendees
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Attendance app running on http://localhost:${PORT}`);
});
