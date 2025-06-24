const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const oracledb = require('oracledb');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const session = require('express-session');

// Load environment variables
dotenv.config();

// Validate required environment variables
const requiredEnvVars = [
  'DB_USER', 'DB_PASSWORD', 'DB_CONNECT_STRING',
  'PORT', 'EMAIL_SERVICE', 'EMAIL_USER', 'EMAIL_PASSWORD',
  'SESSION_SECRET', 'DEFAULT_RECIPIENT_EMAIL'
];

const missingVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingVars.length > 0) {
  console.error('Missing required environment variables:', missingVars.join(', '));
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Oracle Client if path is specified
if (process.env.ORACLE_CLIENT_PATH) {
  try {
    oracledb.initOracleClient({ libDir: process.env.ORACLE_CLIENT_PATH });
    console.log('Oracle Client initialized');
  } catch (err) {
    console.error('Oracle Client initialization error:', err);
  }
}

// Database Configuration
const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  connectString: process.env.DB_CONNECT_STRING,
  poolMin: 2,
  poolMax: 5,
  poolIncrement: 1,
  poolTimeout: 60
};

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
}));

// Email Configuration
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Email Recipient Mapping (will be populated from DB)
let emailMapping = {};

// File Upload Configuration
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Public routes (before authentication)
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadsDir));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Authentication Middleware
function checkAuth(req, res, next) {
  const publicPaths = ['/', '/login', '/uploads', '/api/auth/status', '/api/persons-to-meet'];
  if (publicPaths.some(path => req.path.startsWith(path))) {
    return next();
  }
  if (req.session.authenticated) {
    return next();
  }
  res.redirect('/');
}
app.use(checkAuth);

// API Endpoints
app.get('/api/auth/status', (req, res) => {
  res.json({ authenticated: req.session.authenticated || false });
});

// Get Persons to Meet from Database
app.get('/api/persons-to-meet', async (req, res) => {
    try {
        const sql = `
            select EMAIL_ID, 
                   (select emp_name from emp_mst where ltrim(rtrim(emp_code))=ltrim(rtrim(t.hod_code))) as hod, 
                   (select DEPT_NAME from tbldepartment where hod_code=t.hod_code and rownum=1) as dept
            from tbldepartment t 
            where email_id is not null and DEPT_NAME is not null 
            group by EMAIL_ID, hod_code
        `;
        
        const result = await executeSql(sql, [], { outFormat: oracledb.OUT_FORMAT_OBJECT });
        
        // Update emailMapping with the latest data
        emailMapping = {};
        result.rows.forEach(row => {
            // Map department to email
            emailMapping[row.DEPT] = row.EMAIL_ID;
        });

        const persons = result.rows.map(row => ({
            name: row.HOD,
            department: row.DEPT,
            email: row.EMAIL_ID
        }));

        res.json(persons);
    } catch (err) {
        console.error('Error fetching persons to meet:', err);
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// Get Planned Visitors
app.get('/api/planned-visitors', async (req, res) => {
    try {
        const sql = `
            SELECT VISITOR_ID, FULL_NAME, PERSON_TO_MEET, PURPOSE_OF_VISIT, PHONE_NUMBER,
                   TO_CHAR(PLANNED_DATE, 'YYYY-MM-DD HH24:MI:SS') AS PLANNED_DATE,
                   TO_CHAR(TIME_IN, 'YYYY-MM-DD HH24:MI:SS') AS TIME_IN,
                   VISITOR_PHOTO_PATH
            FROM VISITORS
            WHERE VISITOR_TYPE = 'P' 
              AND TIME_IN IS NULL
              AND TRUNC(PLANNED_DATE) = TRUNC(SYSDATE)
            ORDER BY PLANNED_DATE ASC
        `;
        
        const result = await executeSql(sql, [], { outFormat: oracledb.OUT_FORMAT_OBJECT });
        res.json(result.rows || []);
    } catch (err) {
        console.error('Error fetching planned visitors:', err);
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// Login Endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === 'admin' && password === '123456') {
    req.session.authenticated = true;
    res.json({ success: true, redirect: '/frontend.html' });
  } else {
    res.json({ success: false, message: 'Invalid credentials' });
  }
});

// Logout Endpoint
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

// Database Pool Initialization
async function initializeDbPool() {
  try {
    await oracledb.createPool(dbConfig);
    console.log('Oracle Database connection pool initialized!');
  } catch (err) {
    console.error('Error initializing Oracle Database pool:', err);
    process.exit(1);
  }
}

// Database Query Execution
async function executeSql(sql, binds = [], options = {}) {
  let connection;
  try {
    connection = await oracledb.getConnection();
    const result = await connection.execute(sql, binds, options);
    return result;
  } catch (err) {
    console.error('SQL execution error:', err);
    throw err;
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error('Error closing connection:', err);
      }
    }
  }
}

// Email Notification Function
async function sendNotificationEmail({ visitorName, personToMeet, purpose, phoneNumber, timeIn, photoUrl, req }) {
  const toEmail = emailMapping[personToMeet] || process.env.DEFAULT_RECIPIENT_EMAIL;
  const fullPhotoUrl = photoUrl ? `${req.protocol}://${req.get('host')}${photoUrl}` : null;

  const mailOptions = {
    from: `"Visitor Management System" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: `Visitor Notification: ${visitorName} is here to see you`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #3498db;">Visitor Notification</h2>
        <p><strong>Visitor Name:</strong> ${visitorName}</p>
        <p><strong>Phone Number:</strong> ${phoneNumber}</p>
        <p><strong>Purpose:</strong> ${purpose}</p>
        <p><strong>Time In:</strong> ${timeIn}</p>
        ${fullPhotoUrl ? `
        <p><strong>Photo:</strong></p>
        <a href="${fullPhotoUrl}" target="_blank">
          <img src="${fullPhotoUrl}" style="max-width: 200px; border: 1px solid #ddd; border-radius: 4px;">
        </a>
        ` : ''}
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="font-size: 0.9em; color: #777;">
          This is an automated notification from the Visitor Management System.
        </p>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Notification email sent to ${toEmail}`);
  } catch (emailError) {
    console.error('Email sending failed:', emailError);
    throw emailError;
  }
}

app.post('/api/checkin', upload.single('visitorPhoto'), async (req, res) => {
  const { fullName, personToMeet, purposeOfVisit, phoneNumber, visitorId } = req.body;
  const visitorPhotoPath = req.file ? `/uploads/${req.file.filename}` : null;

  // Add validation and logging
  console.log('Check-in request received:', {
    fullName,
    personToMeet,
    purposeOfVisit,
    phoneNumber,
    visitorId,
    hasPhoto: !!req.file
  });

  if (!fullName || !purposeOfVisit || !personToMeet || !phoneNumber) {
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error('Error deleting uploaded file:', err);
      });
    }
    return res.status(400).json({ message: 'Missing required fields' });
  }

  let sql, binds;
  
  if (visitorId) {
    // Check-in for planned visitor - with additional logging
    console.log(`Processing planned visitor check-in for ID: ${visitorId}`);
    
    sql = `UPDATE VISITORS 
           SET TIME_IN = SYSTIMESTAMP, 
               VISITOR_PHOTO_PATH = :visitorPhotoPath 
           WHERE VISITOR_ID = :visitorId
           RETURNING VISITOR_ID, TIME_IN INTO :updatedVisitorId, :updatedTimeIn`;
    
    binds = {
      visitorPhotoPath,
      visitorId: Number(visitorId), // Ensure it's a number
      updatedVisitorId: { type: oracledb.NUMBER, dir: oracledb.BIND_OUT },
      updatedTimeIn: { type: oracledb.DATE, dir: oracledb.BIND_OUT }
    };
  } else {
    // New visitor check-in
    sql = `INSERT INTO VISITORS (FULL_NAME, PERSON_TO_MEET, PURPOSE_OF_VISIT, PHONE_NUMBER, 
              VISITOR_PHOTO_PATH, VISITOR_TYPE, TIME_IN)
           VALUES (:fullName, :personToMeet, :purposeOfVisit, :phoneNumber, 
              :visitorPhotoPath, 'N', SYSTIMESTAMP)
           RETURNING VISITOR_ID, TIME_IN INTO :visitorId, :timeIn`;
    
    binds = {
      fullName,
      personToMeet,
      purposeOfVisit,
      phoneNumber,
      visitorPhotoPath,
      visitorId: { type: oracledb.NUMBER, dir: oracledb.BIND_OUT },
      timeIn: { type: oracledb.DATE, dir: oracledb.BIND_OUT }
    };
  }

  const options = { autoCommit: true };

  try {
    const result = await executeSql(sql, binds, options);
    
    // Enhanced logging
   // console.log('Database operation result:', result);
    
    const visitorIdOut = visitorId ? result.outBinds.updatedVisitorId[0] : result.outBinds.visitorId[0];
    const timeIn = visitorId ? result.outBinds.updatedTimeIn[0] : result.outBinds.timeIn[0];
    
    console.log(`Visitor ${visitorIdOut} checked in at ${timeIn}`);

    await sendNotificationEmail({
      visitorName: fullName,
      personToMeet,
      purpose: purposeOfVisit,
      phoneNumber,
      timeIn: timeIn.toLocaleString(),
      photoUrl: visitorPhotoPath,
      req
    });

    res.status(201).json({ 
      message: 'Visitor checked in successfully!', 
      visitorId: visitorIdOut, 
      visitorPhotoPath,
      personToMeet,
      timeIn // Include timeIn in response for debugging
    });
  } catch (err) {
    console.error('Error during check-in:', err);
    
    if (req.file) {
      fs.unlink(req.file.path, (unlinkErr) => {
        if (unlinkErr) console.error('Error deleting uploaded file after DB error:', unlinkErr);
      });
    }
    
    res.status(500).json({ 
      message: 'Error checking in visitor.', 
      error: err.message,
      sql: sql, // Include SQL in response for debugging
      binds: binds // Include binds in response for debugging
    });
  }
});
// Check-Out Visitor
app.put('/api/checkout/:id', async (req, res) => {
  const visitorId = req.params.id;

  const sql = `UPDATE VISITORS SET TIME_OUT = SYSTIMESTAMP WHERE VISITOR_ID = :visitorId AND TIME_OUT IS NULL`;
  const binds = { visitorId };
  const options = { autoCommit: true };

  try {
    const result = await executeSql(sql, binds, options);
    if (result.rowsAffected && result.rowsAffected > 0) {
      res.json({ message: 'Visitor checked out successfully!' });
    } else {
      res.status(404).json({ message: 'Visitor not found or already checked out.' });
    }
  } catch (err) {
    res.status(500).json({ message: 'Error checking out visitor.', error: err.message });
  }
});

app.get('/api/current', async (req, res) => {
  try {
    const result = await executeSql(
      `SELECT VISITOR_ID, FULL_NAME, PERSON_TO_MEET, PURPOSE_OF_VISIT, PHONE_NUMBER,
       TO_CHAR(TIME_IN, 'YYYY-MM-DD HH24:MI:SS') AS TIME_IN, 
       VISITOR_PHOTO_PATH
       FROM VISITORS
       WHERE TIME_OUT IS NULL 
       AND TIME_IN IS NOT NULL
       ORDER BY TIME_IN DESC`,
      [],
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    
    res.json(result.rows || []);
  } catch (err) {
    console.error('Error fetching current visitors:', err);
    res.status(500).json({ 
      error: 'Database error',
      details: err.message 
    });
  }
});

// Search Visitors
app.get('/api/search', async (req, res) => {
    const { type, query } = req.query;

    if (!type || !query) {
        return res.status(400).json({ message: 'Missing search parameters' });
    }

    try {
        let sql;
        if (type === 'current') {
            sql = `SELECT * FROM VISITORS
                  WHERE TIME_OUT IS NULL AND VISITOR_TYPE = 'N'
                  AND (UPPER(FULL_NAME) LIKE UPPER(:query)
                  OR UPPER(PERSON_TO_MEET) LIKE UPPER(:query)
                  OR UPPER(PURPOSE_OF_VISIT) LIKE UPPER(:query))`;
        } else if (type === 'planned') {
            sql = `SELECT * FROM VISITORS
                  WHERE VISITOR_TYPE = 'P' AND TIME_IN IS NULL
                  AND TRUNC(PLANNED_DATE) = TRUNC(SYSDATE)
                  AND (UPPER(FULL_NAME) LIKE UPPER(:query)
                  OR UPPER(PERSON_TO_MEET) LIKE UPPER(:query)
                  OR UPPER(PURPOSE_OF_VISIT) LIKE UPPER(:query))`;
        } else {
            return res.status(400).json({ message: 'Invalid search type' });
        }

        const binds = { query: `%${query}%` };
        const options = { outFormat: oracledb.OUT_FORMAT_OBJECT };
        const result = await executeSql(sql, binds, options);

        res.json(result.rows || []);
    } catch (err) {
        console.error('Search error:', err);
        res.status(500).json({ message: 'Error performing search', error: err.message });
    }
});

// Serve Frontend
app.get('/frontend.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend.html'));
});

// Start Server
async function startServer() {
  try {
    await initializeDbPool();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Login page: http://localhost:${PORT}/`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();

// Cleanup on exit
process.once('SIGTERM', async () => {
  await oracledb.getPool().close();
  console.log('Database pool closed');
  process.exit(0);
});

process.once('SIGINT', async () => {
  await oracledb.getPool().close();
  console.log('Database pool closed');
  process.exit(0);
});