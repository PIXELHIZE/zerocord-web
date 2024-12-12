const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const csurf = require('csurf');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const db = require('./db');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const winston = require('winston');
const multer = require('multer');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const failedLoginAttempts = {};

const app = express();
const port = 3000;



// Winston 로거 설정
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// 사용자 권한에 따른 레코드 필터링 함수
function getPermissionBasedQuery(userPermissionLevel) {
  return `
    SELECT * FROM records 
    WHERE privacy_importance >= ? AND privacy_importance <= 5
  `;
}

// 권한 확인 및 쿼리 실행 미들웨어
function checkPermissionAndExecuteQuery(req, res, next) {
  const userPermissionLevel = req.session.user.permission_level;
  
  if (userPermissionLevel === undefined) {
    logger.error(`Permission level is undefined for user: ${req.session.user.username}`);
    return res.status(500).json({ error: 'User permission level is undefined' });
  }

  const query = getPermissionBasedQuery(userPermissionLevel);
  
  db.all(query, [userPermissionLevel], (err, rows) => {
    if (err) {
      logger.error(`Failed to fetch records: ${err.message}`);
      return res.status(500).json({ error: 'Failed to fetch records' });
    }
    req.filteredRecords = rows;
    next();
  });
}

// Multer 설정 (파일을 로컬에 저장)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

// Helmet으로 보안 헤더 설정
app.use(helmet());

// CORS 설정 (프론트엔드가 다른 포트에서 작동하므로 허용 설정)
app.use(cors({
  origin: 'http://localhost:4321', // 프론트엔드가 실행되는 도메인
  credentials: true // 세션 쿠키 허용
}));

// CSRF 보호 미들웨어 설정
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    secure: false  // HTTPS 환경에서는 true로 설정
  }
});

// body-parser 설정
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

// 세션 설정
app.use(session({
  secret: 'nFN=RdG%Ke$xsYZ)W,B7aPA+Z._DiKU1;7g9D6i,$f6tvDd+0U', // 임시
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, // XSS 공격 방지
    secure: false,  // HTTPS 환경에서는 true로 설정해야 함
    maxAge: 1000 * 60 * 30 // 30분 세션 유지
  }
}));

// 세션 고정 공격 방지 및 사용자 인증 미들웨어
const authenticateSession = (req, res, next) => {
  if (!req.session.user) {
    logger.info('Session details after login', {
      sessionId: req.sessionID,
      user: req.session.user || "Unable to verify user value"
    });
    logger.warn(`Unauthorized access attempt from IP: ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized' });
  }
  logger.info('Session details after login', {
    sessionId: req.sessionID,
    user: req.session.user || "Unable to verify user value"
  });
  next();
};

// 로그인 시 세션 고정 공격 방지를 위한 세션 재생성
const regenerateSession = (req, callback) => {
  req.session.regenerate((err) => {
    if (err) return callback(err);

    // 새 세션에 사용자 데이터 저장
    req.session.user = req.session.tempUser; // tempUser를 임시 데이터로 활용
    delete req.session.tempUser; // 필요 없어진 데이터 제거
    callback(null);
  });
};



/*
// IP 반복 시도 차단 (Rate Limiting)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 15, // 15분 동안 최대 100번 요청 허용
  message: 'Too many requests from this IP, please try again after 15 minutes.'
});

app.use(limiter);
*/

const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 login
  message: '요청이 너무 많습니다. 나중에 다시 시도 하십시오.',
  standardHeaders: true,
  legacyHeaders: false,
});

const readRecordsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 read
  message: '요청이 너무 많습니다. 나중에 다시 시도 하십시오.',
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, // 5 upload
  message: '요청이 너무 많습니다. 나중에 다시 시도 하십시오.',
  standardHeaders: true,
  legacyHeaders: false,
});

// 회원가입 (관리자만 가능)
app.post('/register', csrfProtection, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    logger.error('Registration failed: Missing username or password');
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  // 사용자 등록
  const stmt = db.prepare('INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)');
  stmt.run(username, hashedPassword, function (err) {
    if (err) {
      if (err.code === 'SQLITE_CONSTRAINT') {
        logger.error(`Registration failed: Username already exists - ${username}`);
        return res.status(400).json({ error: 'Username already exists' });
      }
      logger.error(`Registration failed: ${err.message}`);
      return res.status(500).json({ error: 'Failed to register user' });
    }
    logger.info(`User registered successfully: ${username}`);
    res.status(201).json({ message: 'User registered successfully' });
  });
  stmt.finalize();
});

const checkUserPermission = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// 기록 업로드
app.post('/upload', authenticateSession, uploadLimiter, upload.single('file'), async (req, res) => {
  const { event_time, source, summary, full_content, location, privacy_importance } = req.body;
  const userId = req.session.user.id;

  let filePath = null;
  if (req.file) {
    filePath = path.relative(__dirname, req.file.path);
  }

  try {
    // 기록 DB에 저장
    const stmt = db.prepare(`
      INSERT INTO records (user_id, event_time, source, summary, full_content, file_path, location, privacy_importance)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run([userId, event_time, source, summary, full_content, filePath, location, privacy_importance], function (err) {
      if (err) {
        logger.error(`Record upload failed: ${err.message}`);
        return res.status(500).json({ error: 'Failed to upload record' });
      }
      logger.info(`Record uploaded successfully: ${event_time}`);
      res.status(201).json({ message: 'Record uploaded successfully', filePath });
    });
    stmt.finalize();
  } catch (error) {
    logger.error(`Failed to upload file: ${error.message}`);
    res.status(500).json({ error: 'Failed to upload file' });
  }
});

app.get('/files/:filename', authenticateSession, (req, res) => {
  const { filename } = req.params;
  const filePath = path.join(__dirname, decodeURIComponent(filename)); // 파일명 디코딩 후 경로 생성
  console.log("파일 다운로드 시도")
  // 파일 존재 및 접근성 확인
  fs.stat(filePath, (err, stats) => {
    if (err) {
      logger.error(`File access error for ${filePath}: ${err.message}`);
      return res.status(404).send('File not found or inaccessible');
    }

    // 파일 크기 확인
    if (stats.size === 0) {
      logger.error(`File is empty: ${filePath}`);
      return res.status(404).send('File is empty');
    }

    // 다운로드를 위해 Content-Disposition 헤더 설정
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    // 파일 전송
    res.sendFile(filePath, (err) => {
      if (err) {
        logger.error(`Error sending file ${filePath}: ${err.message}`);
        res.status(500).send('Error sending file');
      }
    });
  });
});


// 기록 검색
app.get('/search', authenticateSession, readRecordsLimiter, (req, res) => {
  const { keyword, searchType, startDate, endDate, privacyImportance } = req.query;
  const userPermissionLevel = req.session.user.permission_level;

  if (userPermissionLevel === undefined) {
    logger.error(`Permission level is undefined for user: ${req.session.user.username}`);
    return res.status(500).json({ error: 'User permission level is undefined' });
  }

  let query = `
    SELECT id, event_time, source, summary, location, privacy_importance
    FROM records 
    WHERE privacy_importance >= ? AND privacy_importance <= ?
  `;
  let params = [
    Math.max(userPermissionLevel, parseInt(privacyImportance) || 0),
    5
  ];

  if (startDate && endDate) {
    query += ' AND event_time BETWEEN ? AND ?';
    params.push(startDate, endDate);
  }

  if (keyword) {
    if (searchType === 'content') {
      query += ' AND (summary LIKE ? OR full_content LIKE ?)';
      params.push(`%${keyword}%`, `%${keyword}%`);
    } else if (searchType === 'source') {
      query += ' AND source LIKE ?';
      params.push(`%${keyword}%`);
    } else if (searchType === 'location') {
      query += ' AND location LIKE ?';
      params.push(`%${keyword}%`);
    }
  }

  db.all(query, params, (err, rows) => {
    if (err) {
      logger.error(`Search failed: ${err.message}`);
      return res.status(500).json({ error: 'Failed to search records' });
    }
    logger.info('Records searched successfully');
    res.status(200).json(rows);
  });
});




// 사용자 권한 레벨 가져오기
app.get('/user-permission', checkUserPermission, (req, res) => {
  res.json({ permissionLevel: req.session.user.permission_level });
});

// 로그인
app.post('/login',  loginLimiter, csrfProtection, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    logger.error('Login failed: Missing username or password');
    return res.status(400).json("사용자 이름과 비밀번호가 필요합니다");
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      logger.error(`Login failed: ${err.message}`);
      return res.status(500).json("로그인에 실패했습니다");
    }
    if (!user) {
      logger.warn(`Login attempt with non-existent username: ${username}`);
      return res.status(400).json("유저를 찾을 수 없습니다");
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      logger.warn(`Login attempt with invalid credentials: ${username}`);
      return res.status(403).json("암호가 일치하지 않습니다");
    }

    regenerateSession(req, (err) => {
      if (err) {
        logger.error(`Failed to regenerate session: ${err.message}`);
        return res.status(500).json("세션 재생성에 실패했습니다");
      }
      // 세션에 사용자 정보 저장
      req.session.user = {
        id: user.id,
        username: user.username,
        is_admin: user.is_admin === 1,
        permission_level: user.permission_level
      };
      logger.info(`Session created for user: ${username}`, {
        userId: user.id,
        permissionLevel: user.permission_level
      });
      logger.info(`User logged in successfully: ${username}`);
      res.status(200).json("성공적으로 로그인되었습니다");
    });
  });
});

// 로그아웃
app.post('/logout', authenticateSession, (req, res) => {
  const username = req.session.user ? req.session.user.username : 'Unknown user';
  req.session.destroy((err) => {
    if (err) {
      logger.error(`Logout failed: ${err.message}`);
      return res.status(500).json({ error: 'Failed to log out' });
    }
    logger.info(`User logged out successfully: ${username}`);
    res.status(200).json({ message: 'Logged out successfully' });
  });
});

// server.js

// 로그인 상태 확인 API
app.get('/check-auth', (req, res) => {
  if (req.session.user) {
    res.json({ isLoggedIn: true });
  } else {
    res.json({ isLoggedIn: false });
  }
});

// 기록 조회
app.get('/records', authenticateSession, readRecordsLimiter, checkPermissionAndExecuteQuery, (req, res) => {
  const query = `
    SELECT id, event_time, source, summary, location, privacy_importance
    FROM records
    WHERE privacy_importance >= ? AND privacy_importance <= 5
    ORDER BY event_time DESC
  `;
  
  db.all(query, [req.session.user.permission_level], (err, rows) => {
    if (err) {
      logger.error(`Failed to fetch records: ${err.message}`);
      return res.status(500).json({ error: 'Failed to fetch records' });
    }
    logger.info(`Records fetched successfully for user: ${req.session.user.username}`);
    res.status(200).json(rows);
  });
});

app.get('/records/:id', authenticateSession, (req, res) => {
  logger.info('Record details request', {
    userId: req.session.user?.id,
    username: req.session.user?.username,
    requestedId: req.params.id
  });
  const { id } = req.params;
  const query = `
    SELECT *
    FROM records
    WHERE id = ? AND privacy_importance >= ? AND privacy_importance <= 5
  `;
  
  db.get(query, [id, req.session.user.permission_level], (err, row) => {
    if (err) {
      logger.error(`Failed to fetch record details: ${err.message}`);
      return res.status(500).json({ error: 'Failed to fetch record details' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Record not found or insufficient permissions' });
    }
    logger.info(`Record details fetched successfully for id: ${id}`);
    res.status(200).json(row);
  });
});

app.put('/records/:id', authenticateSession, csrfProtection, (req, res) => {
  if (!req.session.user.is_admin) {
    return res.status(403).json({ error: 'Only admins can modify records' });
  }

  const { id } = req.params;
  const { event_time, source, summary, full_content, file_path, location, privacy_importance } = req.body;

  const query = `
    UPDATE records
    SET event_time = ?, source = ?, summary = ?, full_content = ?, file_path = ?, location = ?, privacy_importance = ?
    WHERE id = ?
  `;

  db.run(query, [event_time, source, summary, full_content, file_path, location, privacy_importance, id], function(err) {
    if (err) {
      logger.error(`Failed to update record: ${err.message}`);
      return res.status(500).json({ error: 'Failed to update record' });
    }
    logger.info(`Record updated successfully: ${id}`);
    res.status(200).json({ message: 'Record updated successfully' });
  });
});

// 기록 삭제 (관리자 전용)
app.delete('/records/:id', authenticateSession, csrfProtection, (req, res) => {
  if (!req.session.user.is_admin) {
    return res.status(403).json({ error: 'Only admins can delete records' });
  }

  const { id } = req.params;

  db.run('DELETE FROM records WHERE id = ?', [id], function(err) {
    if (err) {
      logger.error(`Failed to delete record: ${err.message}`);
      return res.status(500).json({ error: 'Failed to delete record' });
    }
    logger.info(`Record deleted successfully: ${id}`);
    res.status(200).json({ message: 'Record deleted successfully' });
  });
});

// CSRF 토큰 발급
app.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
  logger.info("User issues CSRF token");
});

app.post('/admin/create-account', authenticateSession, async (req, res) => {
  const { username, password, permission } = req.body;

  if (!req.session.user.is_admin) {
    return res.status(403).json({ error: 'Only admins can create accounts' });
  }

  if (!username || !password || !permission) {
    return res.status(400).json({ error: 'Missing username, password, or permission' });
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const stmt = db.prepare('INSERT INTO users (username, password, permission_level) VALUES (?, ?, ?)');
  stmt.run([username, hashedPassword, permission], function (err) {
    if (err) {
      if (err.code === 'SQLITE_CONSTRAINT') {
        return res.status(400).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: 'Failed to create account' });
    }
    res.status(201).json({ message: 'Account created successfully' });
  });
});

app.get('/admin/accounts', authenticateSession, (req, res) => {
  if (!req.session.user.is_admin) {
    return res.status(403).json({ error: 'Only admins can view accounts' });
  }

  db.all('SELECT username, permission_level FROM users', [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch accounts' });
    }
    res.status(200).json(rows);
  });
});

app.post('/admin/delete-account', authenticateSession, (req, res) => {
  const { username } = req.body;

  if (!req.session.user.is_admin) {
    return res.status(403).json({ error: 'Only admins can delete accounts' });
  }

  db.run('DELETE FROM users WHERE username = ?', [username], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete account' });
    }
    res.status(200).json({ message: 'Account deleted successfully' });
  });
});

app.post('/admin/reset-password', authenticateSession, async (req, res) => {
  const { username, newPassword } = req.body;

  if (!req.session.user.is_admin) {
    return res.status(403).json({ error: 'Only admins can reset passwords' });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 12);
  db.run('UPDATE users SET password = ? WHERE username = ?', [hashedPassword, username], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to reset password' });
    }
    res.status(200).json({ message: 'Password reset successfully' });
  });
});

app.post('/admin/update-permission', authenticateSession, (req, res) => {
  const { username, permission } = req.body;

  if (!req.session.user.is_admin) {
    return res.status(403).json({ error: 'Only admins can update permissions' });
  }

  db.run('UPDATE users SET permission_level = ? WHERE username = ?', [permission, username], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to update permission' });
    }
    res.status(200).json({ message: 'Permission updated successfully' });
  });
});


// 서버 실행
app.listen(port, () => {
  logger.info(`Server running on http://localhost:${port}`);
});
