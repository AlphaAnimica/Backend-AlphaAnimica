const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const stripe = require('stripe')('sk_test_51Nw...your_test_key_here...'); // Replace with your Stripe test secret key

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Database setup
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database');
    initializeDatabase();
  }
});

// Helper: get active subscription for user
function getActiveSubscription(userId, cb) {
  db.get('SELECT * FROM subscriptions WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP ORDER BY expires_at DESC LIMIT 1', [userId], cb);
}

// Initialize database tables
function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      user_type TEXT NOT NULL CHECK(user_type IN ('trainee', 'clinic', 'admin')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Trainee profiles
    db.run(`CREATE TABLE IF NOT EXISTS trainee_profiles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      phone TEXT,
      location TEXT,
      education TEXT,
      skills TEXT,
      experience TEXT,
      resume_path TEXT,
      profile_photo TEXT,
      university_year TEXT,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Clinic profiles
    db.run(`CREATE TABLE IF NOT EXISTS clinic_profiles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      clinic_name TEXT,
      phone TEXT,
      address TEXT,
      description TEXT,
      website TEXT,
      logo_path TEXT,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Opportunities/Positions
    db.run(`CREATE TABLE IF NOT EXISTS opportunities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      clinic_id INTEGER,
      title TEXT NOT NULL,
      description TEXT,
      requirements TEXT,
      location TEXT,
      is_paid BOOLEAN DEFAULT 0,
      salary_range TEXT,
      level TEXT,
      skills_required TEXT,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (clinic_id) REFERENCES users (id)
    )`);

    // Applications
    db.run(`CREATE TABLE IF NOT EXISTS applications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      trainee_id INTEGER,
      opportunity_id INTEGER,
      status TEXT DEFAULT 'pending',
      cover_letter TEXT,
      resume_path TEXT,
      applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (trainee_id) REFERENCES users (id),
      FOREIGN KEY (opportunity_id) REFERENCES opportunities (id)
    )`);

    // Interviews
    db.run(`CREATE TABLE IF NOT EXISTS interviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      application_id INTEGER,
      scheduled_date DATETIME,
      status TEXT DEFAULT 'scheduled',
      notes TEXT,
      type TEXT,
      meeting_link TEXT,
      location TEXT,
      FOREIGN KEY (application_id) REFERENCES applications (id)
    )`);

    // Subscriptions/Payments
    db.run(`CREATE TABLE IF NOT EXISTS subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      plan_type TEXT,
      applications_limit INTEGER,
      opportunities_limit INTEGER,
      expires_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Subscription plans
    db.run(`CREATE TABLE IF NOT EXISTS subscription_plans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      price REAL NOT NULL,
      applications_limit INTEGER,
      opportunities_limit INTEGER,
      duration_days INTEGER,
      description TEXT
    )`);

    // Add clinic_reviews table
    // (id, clinic_id, trainee_id, rating, feedback, created_at)
    db.run(`CREATE TABLE IF NOT EXISTS clinic_reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      clinic_id INTEGER,
      trainee_id INTEGER,
      rating INTEGER CHECK(rating >= 1 AND rating <= 5),
      feedback TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (clinic_id) REFERENCES users (id),
      FOREIGN KEY (trainee_id) REFERENCES users (id),
      UNIQUE(clinic_id, trainee_id)
    )`);

    // Add clinic_photos table
    // (id, clinic_id, photo_path, uploaded_at)
    db.run(`CREATE TABLE IF NOT EXISTS clinic_photos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      clinic_id INTEGER,
      photo_path TEXT,
      uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (clinic_id) REFERENCES users (id)
    )`);

    // Payments table
    db.run(`CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      plan_id INTEGER,
      amount REAL,
      paid_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      method TEXT,
      status TEXT,
      reference TEXT,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (plan_id) REFERENCES subscription_plans (id)
    )`);
  });
}

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage });

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, 'your-secret-key', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'alphaanimica@gmail.com',
    pass: 'your-app-password' // Replace with real app password
  }
});

function sendEmail(to, subject, text) {
  transporter.sendMail({ from: 'alphaanimica@gmail.com', to, subject, text }, (err, info) => {
    if (err) console.error('Email error:', err);
  });
}

// Routes

// Authentication
const registrationUpload = upload.fields([
  { name: 'resume', maxCount: 1 },
  { name: 'logo', maxCount: 1 },
  { name: 'profilePhoto', maxCount: 1 }
]);

app.post('/api/register', registrationUpload, async (req, res) => {
  try {
    const { email, password, name, userType } = req.body;
    console.log('Register attempt:', { email, name, userType });
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO users (email, password, name, user_type) VALUES (?, ?, ?, ?)',
      [email, hashedPassword, name, userType],
      function(err) {
        if (err) {
          console.error('Registration error:', err);
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Email already exists' });
          }
          return res.status(500).json({ error: 'Registration failed' });
        }
        const userId = this.lastID;
        // Handle profile creation
        if (userType === 'trainee') {
          const { phone, location, education, skills, experience, universityYear } = req.body;
          const resumePath = req.files && req.files['resume'] ? req.files['resume'][0].path : null;
          const profilePhotoPath = req.files && req.files['profilePhoto'] ? req.files['profilePhoto'][0].path : null;
          db.run(
            'INSERT INTO trainee_profiles (user_id, phone, location, education, skills, experience, resume_path, profile_photo, university_year) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [userId, phone, location, education, skills, experience, resumePath, profilePhotoPath, universityYear],
            function(profileErr) {
              if (profileErr) {
                console.error('Trainee profile error:', profileErr);
                return res.status(500).json({ error: 'Profile creation failed' });
              }
              const token = jwt.sign({ id: userId, email, userType }, 'your-secret-key');
              res.json({ token, user: { id: userId, email, name, userType } });
            }
          );
        } else if (userType === 'clinic') {
          const { clinicName, clinicPhone, address, description, website } = req.body;
          const logoPath = req.files && req.files['logo'] ? req.files['logo'][0].path : null;
          db.run(
            'INSERT INTO clinic_profiles (user_id, clinic_name, phone, address, description, website, logo_path) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [userId, clinicName, clinicPhone, address, description, website, logoPath],
            function(profileErr) {
              if (profileErr) {
                console.error('Clinic profile error:', profileErr);
                return res.status(500).json({ error: 'Profile creation failed' });
              }
              const token = jwt.sign({ id: userId, email, userType }, 'your-secret-key');
              res.json({ token, user: { id: userId, email, name, userType } });
            }
          );
        } else if (userType === 'admin') {
          // Admin does not need a profile
          const token = jwt.sign({ id: userId, email, userType }, 'your-secret-key');
          res.json({ token, user: { id: userId, email, name, userType } });
        } else {
          // Should not happen
          const token = jwt.sign({ id: userId, email, userType }, 'your-secret-key');
          res.json({ token, user: { id: userId, email, name, userType } });
        }
      }
    );
  } catch (error) {
    console.error('Registration server error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ id: user.id, email: user.email, userType: user.user_type }, 'your-secret-key');
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, userType: user.user_type } });
  });
});

// Trainee routes
app.post('/api/trainee/profile', authenticateToken, upload.fields([
  { name: 'resume', maxCount: 1 },
  { name: 'profilePhoto', maxCount: 1 }
]), (req, res) => {
  // Admin can specify user_id in body, otherwise use req.user.id
  const targetUserId = req.user.userType === 'admin' && req.body.user_id ? req.body.user_id : req.user.id;
  const { phone, location, education, skills, experience, universityYear } = req.body;
  const resumePath = req.files && req.files['resume'] ? req.files['resume'][0].path : null;
  const profilePhotoPath = req.files && req.files['profilePhoto'] ? req.files['profilePhoto'][0].path : null;

  db.get('SELECT * FROM trainee_profiles WHERE user_id = ?', [targetUserId], (err, existing) => {
    if (err) return res.status(500).json({ error: 'Profile fetch failed' });
    const merged = {
      phone: phone !== undefined ? phone : existing?.phone,
      location: location !== undefined ? location : existing?.location,
      education: education !== undefined ? education : existing?.education,
      skills: skills !== undefined ? skills : existing?.skills,
      experience: experience !== undefined ? experience : existing?.experience,
      resume_path: resumePath !== null ? resumePath : existing?.resume_path,
      profile_photo: profilePhotoPath !== null ? profilePhotoPath : existing?.profile_photo,
      university_year: universityYear !== undefined ? universityYear : existing?.university_year
    };
    if (existing) {
      db.run(
        'UPDATE trainee_profiles SET phone = ?, location = ?, education = ?, skills = ?, experience = ?, resume_path = ?, profile_photo = ?, university_year = ? WHERE user_id = ?',
        [merged.phone, merged.location, merged.education, merged.skills, merged.experience, merged.resume_path, merged.profile_photo, merged.university_year, targetUserId],
        function(err) {
          if (err) return res.status(500).json({ error: 'Profile update failed' });
          res.json({ message: 'Profile updated successfully' });
        }
      );
    } else {
      db.run(
        'INSERT INTO trainee_profiles (user_id, phone, location, education, skills, experience, resume_path, profile_photo, university_year) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [targetUserId, merged.phone, merged.location, merged.education, merged.skills, merged.experience, merged.resume_path, merged.profile_photo, merged.university_year],
        function(err) {
          if (err) return res.status(500).json({ error: 'Profile creation failed' });
          res.json({ message: 'Profile created successfully' });
        }
      );
    }
  });
});

app.get('/api/trainee/profile', authenticateToken, (req, res) => {
  db.get('SELECT * FROM trainee_profiles WHERE user_id = ?', [req.user.id], (err, profile) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(profile || {});
  });
});

// Public: Get trainee profile by user ID
app.get('/api/trainee/profile/:id', (req, res) => {
  db.get('SELECT * FROM trainee_profiles WHERE user_id = ?', [req.params.id], (err, profile) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    res.json(profile);
  });
});

// Clinic routes
app.post('/api/clinic/profile', authenticateToken, upload.single('logo'), (req, res) => {
  // Admin can specify user_id in body, otherwise use req.user.id
  const targetUserId = req.user.userType === 'admin' && req.body.user_id ? req.body.user_id : req.user.id;
  const { clinic_name, phone, address, description, website } = req.body;
  const logoPath = req.file ? req.file.path : null;

  db.get('SELECT * FROM clinic_profiles WHERE user_id = ?', [targetUserId], (err, existing) => {
    if (err) return res.status(500).json({ error: 'Server error' });

    if (existing) {
      // Update existing profile
      db.run(
        'UPDATE clinic_profiles SET clinic_name = ?, phone = ?, address = ?, description = ?, website = ?, logo_path = ? WHERE user_id = ?',
        [clinic_name, phone, address, description, website, logoPath || existing.logo_path, targetUserId],
        function (err) {
          if (err) return res.status(500).json({ error: 'Profile update failed' });
          res.json({ message: 'Profile updated successfully' });
        }
      );
    } else {
      // Insert new profile
      db.run(
        'INSERT INTO clinic_profiles (user_id, clinic_name, phone, address, description, website, logo_path) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [targetUserId, clinic_name, phone, address, description, website, logoPath],
        function (err) {
          if (err) return res.status(500).json({ error: 'Profile creation failed' });
          res.json({ message: 'Profile created successfully' });
        }
      );
    }
  });
});

app.get('/api/clinic/profile', authenticateToken, (req, res) => {
  db.get('SELECT * FROM clinic_profiles WHERE user_id = ?', [req.user.id], (err, profile) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(profile || {});
  });
});

// Public: Get clinic profile by user ID
app.get('/api/clinic/profile/:id', (req, res) => {
  db.get('SELECT * FROM clinic_profiles WHERE user_id = ?', [req.params.id], (err, profile) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    res.json(profile);
  });
});

// Clinic photo upload endpoint
app.post('/api/clinic/photos', authenticateToken, upload.array('photos', 10), (req, res) => {
  if (req.user.userType !== 'clinic' && req.user.userType !== 'admin') {
    return res.status(403).json({ error: 'Only clinics or admins can upload photos' });
  }
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No photos uploaded' });
  }
  const clinicId = req.user.id;
  const stmt = db.prepare('INSERT INTO clinic_photos (clinic_id, photo_path) VALUES (?, ?)');
  req.files.forEach(file => {
    stmt.run(clinicId, file.path);
  });
  stmt.finalize();
  res.json({ message: 'Photos uploaded successfully' });
});

// Get all photos for a clinic
app.get('/api/clinic/:id/photos', (req, res) => {
  db.all('SELECT * FROM clinic_photos WHERE clinic_id = ? ORDER BY uploaded_at DESC', [req.params.id], (err, photos) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch photos' });
    res.json(photos);
  });
});

// Opportunities routes
app.post('/api/opportunities', authenticateToken, (req, res) => {
  // Admin can specify clinic_id in body, otherwise use req.user.id
  const clinicId = req.user.userType === 'admin' && req.body.clinic_id ? req.body.clinic_id : req.user.id;
  const { title, description, requirements, location, isPaid, salaryRange, level, skillsRequired } = req.body;
  // ENFORCE SUBSCRIPTION LIMIT for clinics
  getActiveSubscription(clinicId, (err, sub) => {
    if (err) return res.status(500).json({ error: 'Failed to check subscription' });
    if (!sub) {
      // No subscription: allow up to 3 free opportunities
      db.get('SELECT COUNT(*) as cnt FROM opportunities WHERE clinic_id = ?', [clinicId], (err2, countRes) => {
        if (err2) return res.status(500).json({ error: 'Failed to check opportunity count' });
        if (countRes.cnt >= 3) return res.status(403).json({ error: 'Free opportunity limit reached. Please subscribe to post more.' });
        db.run(
          'INSERT INTO opportunities (clinic_id, title, description, requirements, location, is_paid, salary_range, level, skills_required) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
          [clinicId, title, description, requirements, location, isPaid, salaryRange, level, skillsRequired],
          function(err3) {
            if (err3) return res.status(500).json({ error: 'Failed to create opportunity' });
            res.json({ id: this.lastID, message: 'Opportunity created successfully (free tier)' });
          }
        );
      });
      return;
    }
    db.get('SELECT COUNT(*) as cnt FROM opportunities WHERE clinic_id = ? AND created_at > ? AND created_at < ?', [clinicId, (() => {
      const days = Number(sub.duration_days);
      if (!days || isNaN(days) || days <= 0) {
        return res.status(500).json({ error: 'Invalid subscription duration.' });
      }
      return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
    })(), sub.expires_at], (err4, countRes) => {
      if (err4) return res.status(500).json({ error: 'Failed to check opportunity count' });
      if (sub.opportunities_limit <= 0) return res.status(403).json({ error: 'Your subscription opportunity limit is exhausted. Please renew or purchase a new plan.' });
      if (countRes.cnt >= sub.opportunities_limit) return res.status(403).json({ error: 'Opportunity limit reached for your subscription' });
      db.run(
        'INSERT INTO opportunities (clinic_id, title, description, requirements, location, is_paid, salary_range, level, skills_required) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [clinicId, title, description, requirements, location, isPaid, salaryRange, level, skillsRequired],
        function(err5) {
          if (err5) return res.status(500).json({ error: 'Failed to create opportunity' });
          // Decrement opportunities_limit
          db.run('UPDATE subscriptions SET opportunities_limit = opportunities_limit - 1 WHERE id = ?', [sub.id]);
          res.json({ id: this.lastID, message: 'Opportunity created successfully' });
        }
      );
    });
  });
});

const getUserFromToken = (req) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return null;
  try {
    return require('jsonwebtoken').verify(token, 'your-secret-key');
  } catch {
    return null;
  }
};

app.get('/api/opportunities', (req, res) => {
  const { location, isPaid, level, skills, search } = req.query;
  const user = getUserFromToken(req);
  let query = `
    SELECT o.*, c.clinic_name, c.address 
    FROM opportunities o 
    JOIN clinic_profiles c ON o.clinic_id = c.user_id 
    WHERE o.status = 'active'
  `;
  const params = [];

  if (user && (user.userType === 'clinic' || user.userType === 'admin')) {
    query += ' AND o.clinic_id = ?';
    params.push(user.id);
  }
  if (location) {
    query += ' AND o.location LIKE ?';
    params.push(`%${location}%`);
  }
  if (isPaid !== undefined) {
    query += ' AND o.is_paid = ?';
    params.push(isPaid);
  }
  if (level) {
    query += ' AND o.level LIKE ?';
    params.push(`%${level}%`);
  }
  if (skills) {
    query += ' AND o.skills_required LIKE ?';
    params.push(`%${skills}%`);
  }
  if (search) {
    query += ' AND (o.title LIKE ? OR o.description LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }

  query += ' ORDER BY o.created_at DESC';

  db.all(query, params, (err, opportunities) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(opportunities);
  });
});

app.get('/api/opportunities/:id', (req, res) => {
  db.get(`
    SELECT o.*, c.clinic_name, c.address, c.description as clinic_description 
    FROM opportunities o 
    JOIN clinic_profiles c ON o.clinic_id = c.user_id 
    WHERE o.id = ?
  `, [req.params.id], (err, opportunity) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!opportunity) return res.status(404).json({ error: 'Opportunity not found' });
    res.json(opportunity);
  });
});

// Applications routes
app.post('/api/applications', authenticateToken, upload.single('resume'), (req, res) => {
  const { opportunityId, coverLetter } = req.body;
  const resumePath = req.file ? req.file.path : null;
  // Check if user has already applied
  db.get('SELECT id FROM applications WHERE trainee_id = ? AND opportunity_id = ?', 
    [req.user.id, opportunityId], (err, existing) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (existing) return res.status(400).json({ error: 'Already applied to this opportunity' });
    // ENFORCE SUBSCRIPTION LIMIT
    getActiveSubscription(req.user.id, (err, sub) => {
      if (err) return res.status(500).json({ error: 'Failed to check subscription' });
      if (!sub) {
        // No subscription: allow up to 3 free applications
        db.get('SELECT COUNT(*) as cnt FROM applications WHERE trainee_id = ?', [req.user.id], (err2, countRes) => {
          if (err2) return res.status(500).json({ error: 'Failed to check application count' });
          if (countRes.cnt >= 3) return res.status(403).json({ error: 'Free application limit reached. Please subscribe to apply to more opportunities.' });
          db.run(
            'INSERT INTO applications (trainee_id, opportunity_id, cover_letter, resume_path) VALUES (?, ?, ?, ?)',
            [req.user.id, opportunityId, coverLetter, resumePath],
            function(err3) {
              if (err3) return res.status(500).json({ error: 'Application failed' });
              res.json({ id: this.lastID, message: 'Application submitted successfully (free tier)' });
            }
          );
        });
        return;
      }
      db.get('SELECT COUNT(*) as cnt FROM applications WHERE trainee_id = ? AND applied_at > ? AND applied_at < ?', [req.user.id, (() => {
        const days = Number(sub.duration_days);
        if (!days || isNaN(days) || days <= 0) {
          return res.status(500).json({ error: 'Invalid subscription duration.' });
        }
        return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
      })(), sub.expires_at], (err4, countRes) => {
        if (err4) return res.status(500).json({ error: 'Failed to check application count' });
        if (sub.applications_limit <= 0) return res.status(403).json({ error: 'Your subscription application limit is exhausted. Please renew or purchase a new plan.' });
        if (countRes.cnt >= sub.applications_limit) return res.status(403).json({ error: 'Application limit reached for your subscription' });
        db.run(
          'INSERT INTO applications (trainee_id, opportunity_id, cover_letter, resume_path) VALUES (?, ?, ?, ?)',
          [req.user.id, opportunityId, coverLetter, resumePath],
          function(err5) {
            if (err5) return res.status(500).json({ error: 'Application failed' });
            // Decrement applications_limit
            db.run('UPDATE subscriptions SET applications_limit = applications_limit - 1 WHERE id = ?', [sub.id]);
            res.json({ id: this.lastID, message: 'Application submitted successfully' });
          }
        );
      });
    });
  });
});

app.get('/api/applications', authenticateToken, (req, res) => {
  // Admin can see all applications
  let query;
  let params = [];
  if (req.user.userType === 'admin') {
    query = `SELECT a.*, o.title, o.location, c.clinic_name, u.name as trainee_name, t.phone, t.education, i.scheduled_date as interview_date, i.notes as interview_notes, i.type as interview_type, i.meeting_link as interview_meeting_link, i.location as interview_location
      FROM applications a 
      JOIN opportunities o ON a.opportunity_id = o.id 
      JOIN clinic_profiles c ON o.clinic_id = c.user_id 
      JOIN users u ON a.trainee_id = u.id 
      LEFT JOIN trainee_profiles t ON a.trainee_id = t.user_id 
      LEFT JOIN (
        SELECT application_id, scheduled_date, notes, type, meeting_link, location
        FROM interviews
        WHERE id IN (
          SELECT MAX(id) FROM interviews GROUP BY application_id
        )
      ) i ON a.id = i.application_id
      ORDER BY a.applied_at DESC`;
  } else if (req.user.userType === 'trainee') {
    query = `SELECT a.*, o.title, o.location, c.clinic_name, i.scheduled_date as interview_date, i.notes as interview_notes, i.type as interview_type, i.meeting_link as interview_meeting_link, i.location as interview_location
      FROM applications a 
      JOIN opportunities o ON a.opportunity_id = o.id 
      JOIN clinic_profiles c ON o.clinic_id = c.user_id 
      LEFT JOIN (
        SELECT application_id, scheduled_date, notes, type, meeting_link, location
        FROM interviews
        WHERE id IN (
          SELECT MAX(id) FROM interviews GROUP BY application_id
        )
      ) i ON a.id = i.application_id
      WHERE a.trainee_id = ?
      ORDER BY a.applied_at DESC`;
    params = [req.user.id];
  } else {
    query = `SELECT a.*, o.title, o.location, u.name as trainee_name, t.phone, t.education, i.scheduled_date as interview_date, i.notes as interview_notes, i.type as interview_type, i.meeting_link as interview_meeting_link, i.location as interview_location
      FROM applications a 
      JOIN opportunities o ON a.opportunity_id = o.id 
      JOIN users u ON a.trainee_id = u.id 
      LEFT JOIN trainee_profiles t ON a.trainee_id = t.user_id 
      LEFT JOIN (
        SELECT application_id, scheduled_date, notes, type, meeting_link, location
        FROM interviews
        WHERE id IN (
          SELECT MAX(id) FROM interviews GROUP BY application_id
        )
      ) i ON a.id = i.application_id
      WHERE o.clinic_id = ?
      ORDER BY a.applied_at DESC`;
    params = [req.user.id];
  }
  db.all(query, params, (err, applications) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(applications);
  });
});

// Interview scheduling
app.post('/api/interviews', authenticateToken, (req, res) => {
  const { applicationId, scheduledDate, notes, type, meetingLink, location } = req.body;
  db.get('SELECT id FROM interviews WHERE application_id = ?', [applicationId], (err, existing) => {
    if (err) return res.status(500).json({ error: 'Failed to check for existing interview' });
    if (existing) {
      // Update existing interview
      db.run(
        'UPDATE interviews SET scheduled_date = ?, notes = ?, type = ?, meeting_link = ?, location = ? WHERE application_id = ?',
        [scheduledDate, notes, type, meetingLink, location, applicationId],
        function(updateErr) {
          if (updateErr) return res.status(500).json({ error: 'Failed to update interview' });
          // Update application status to 'interview'
          db.run(
            'UPDATE applications SET status = ? WHERE id = ?',
            ['interview', applicationId],
            function(appErr) {
              if (appErr) return res.status(500).json({ error: 'Failed to update application status' });
              res.json({ id: existing.id, message: 'Interview updated successfully' });
            }
          );
        }
      );
    } else {
      // Insert new interview
      db.run(
        'INSERT INTO interviews (application_id, scheduled_date, notes, type, meeting_link, location) VALUES (?, ?, ?, ?, ?, ?)',
        [applicationId, scheduledDate, notes, type, meetingLink, location],
        function(insertErr) {
          if (insertErr) return res.status(500).json({ error: 'Failed to schedule interview' });
          // Update application status to 'interview'
          db.run(
            'UPDATE applications SET status = ? WHERE id = ?',
            ['interview', applicationId],
            function(appErr) {
              if (appErr) return res.status(500).json({ error: 'Failed to update application status' });
              res.json({ id: this.lastID, message: 'Interview scheduled successfully' });
            }
          );
        }
      );
    }
  });
});

// Update application status
app.put('/api/applications/:id/status', authenticateToken, (req, res) => {
  const { status } = req.body;
  
  db.run(
    'UPDATE applications SET status = ? WHERE id = ?',
    [status, req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update status' });
      res.json({ message: 'Status updated successfully' });
    }
  );
});

// Update opportunity status
app.put('/api/opportunities/:id/status', authenticateToken, (req, res) => {
  const { status } = req.body;
  
  db.run(
    'UPDATE opportunities SET status = ? WHERE id = ? AND clinic_id = ?',
    [status, req.params.id, req.user.id],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update status' });
      res.json({ message: 'Status updated successfully' });
    }
  );
});

// Update opportunity (clinic only)
app.put('/api/opportunities/:id', authenticateToken, (req, res) => {
  const opportunityId = req.params.id;
  const clinicId = req.user.id;
  const { title, description, requirements, skills_required, location, is_paid, salary_range, level } = req.body;
  db.run(
    'UPDATE opportunities SET title = ?, description = ?, requirements = ?, skills_required = ?, location = ?, is_paid = ?, salary_range = ?, level = ? WHERE id = ? AND clinic_id = ?',
    [title, description, requirements, skills_required, location, is_paid ? 1 : 0, salary_range, level, opportunityId, clinicId],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update opportunity' });
      if (this.changes === 0) return res.status(403).json({ error: 'Not authorized or opportunity not found' });
      res.json({ message: 'Opportunity updated successfully' });
    }
  );
});

// Delete user profile and account
app.delete('/api/profile', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const userType = req.user.userType;
  if (userType === 'trainee' || userType === 'admin') {
    db.run('DELETE FROM trainee_profiles WHERE user_id = ?', [userId], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete trainee profile' });
      db.run('DELETE FROM users WHERE id = ?', [userId], function(err2) {
        if (err2) return res.status(500).json({ error: 'Failed to delete user account' });
        res.json({ message: 'Account and profile deleted successfully' });
      });
    });
  } else if (userType === 'clinic' || userType === 'admin') {
    db.run('DELETE FROM clinic_profiles WHERE user_id = ?', [userId], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete clinic profile' });
      db.run('DELETE FROM users WHERE id = ?', [userId], function(err2) {
        if (err2) return res.status(500).json({ error: 'Failed to delete user account' });
        res.json({ message: 'Account and profile deleted successfully' });
      });
    });
  } else {
    res.status(400).json({ error: 'Invalid user type' });
  }
});

// Delete opportunity (clinic only)
app.delete('/api/opportunities/:id', authenticateToken, (req, res) => {
  const opportunityId = req.params.id;
  const clinicId = req.user.id;
  db.run('DELETE FROM opportunities WHERE id = ? AND clinic_id = ?', [opportunityId, clinicId], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete opportunity' });
    if (this.changes === 0) return res.status(403).json({ error: 'Not authorized or opportunity not found' });
    res.json({ message: 'Opportunity deleted successfully' });
  });
});

// Get all reviews for a clinic
app.get('/api/clinic/:id/reviews', (req, res) => {
  const clinicId = req.params.id;
  db.all(`
    SELECT cr.*, u.name as trainee_name, t.profile_photo
    FROM clinic_reviews cr
    JOIN users u ON cr.trainee_id = u.id
    LEFT JOIN trainee_profiles t ON cr.trainee_id = t.user_id
    WHERE cr.clinic_id = ?
    ORDER BY cr.created_at DESC
  `, [clinicId], (err, reviews) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch reviews' });
    res.json(reviews);
  });
});

// Get rating statistics for a clinic
app.get('/api/clinic/:id/rating-stats', (req, res) => {
  const clinicId = req.params.id;
  db.get(`
    SELECT 
      COUNT(*) as total_reviews,
      AVG(rating) as average_rating,
      COUNT(CASE WHEN rating = 5 THEN 1 END) as five_star,
      COUNT(CASE WHEN rating = 4 THEN 1 END) as four_star,
      COUNT(CASE WHEN rating = 3 THEN 1 END) as three_star,
      COUNT(CASE WHEN rating = 2 THEN 1 END) as two_star,
      COUNT(CASE WHEN rating = 1 THEN 1 END) as one_star
    FROM clinic_reviews 
    WHERE clinic_id = ?
  `, [clinicId], (err, stats) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch rating stats' });
    res.json(stats);
  });
});

// Delete a photo
app.delete('/api/clinic/photos/:photoId', authenticateToken, (req, res) => {
  const photoId = req.params.photoId;
  // Only allow the clinic owner to delete their own photos
  db.get('SELECT * FROM clinic_photos WHERE id = ?', [photoId], (err, photo) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!photo) return res.status(404).json({ error: 'Photo not found' });
    if (photo.clinic_id !== req.user.id && req.user.userType !== 'admin') return res.status(403).json({ error: 'Not authorized' });
    db.run('DELETE FROM clinic_photos WHERE id = ?', [photoId], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete photo' });
      // Optionally, delete the file from disk
      try { require('fs').unlinkSync(photo.photo_path); } catch (e) {}
      res.json({ message: 'Photo deleted successfully' });
    });
  });
});

// Submit or update a review for a clinic
app.post('/api/clinic/:id/review', authenticateToken, (req, res) => {
  if (req.user.userType !== 'trainee' && req.user.userType !== 'admin') {
    return res.status(403).json({ error: 'Only trainees or admins can submit reviews' });
  }
  const clinicId = req.params.id;
  const traineeId = req.user.id;
  const { rating, feedback } = req.body;
  if (!rating || !feedback) {
    return res.status(400).json({ error: 'Rating and feedback are required' });
  }
  db.get('SELECT id FROM clinic_reviews WHERE clinic_id = ? AND trainee_id = ?', [clinicId, traineeId], (err, existing) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (existing) {
      // Update existing review
      db.run('UPDATE clinic_reviews SET rating = ?, feedback = ?, created_at = CURRENT_TIMESTAMP WHERE id = ?', [rating, feedback, existing.id], function(updateErr) {
        if (updateErr) return res.status(500).json({ error: 'Failed to update review' });
        res.json({ message: 'Review updated successfully' });
      });
    } else {
      // Insert new review
      db.run('INSERT INTO clinic_reviews (clinic_id, trainee_id, rating, feedback, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)', [clinicId, traineeId, rating, feedback], function(insertErr) {
        if (insertErr) return res.status(500).json({ error: 'Failed to submit review' });
        res.json({ message: 'Review submitted successfully' });
      });
    }
  });
});

// Admin-only endpoints
app.get('/api/admin/users', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.all('SELECT id, email, name, user_type, created_at FROM users', [], (err, users) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch users' });
    res.json(users);
  });
});

app.delete('/api/admin/users/:id', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const userId = req.params.id;
  db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete user' });
    res.json({ message: 'User deleted successfully' });
  });
});

app.get('/api/admin/opportunities', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.all('SELECT * FROM opportunities', [], (err, opportunities) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch opportunities' });
    res.json(opportunities);
  });
});

app.delete('/api/admin/opportunities/:id', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const opportunityId = req.params.id;
  db.run('DELETE FROM opportunities WHERE id = ?', [opportunityId], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete opportunity' });
    res.json({ message: 'Opportunity deleted successfully' });
  });
});

// --- Admin CRUD for Subscription Plans ---
app.get('/api/admin/subscription-plans', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.all('SELECT * FROM subscription_plans', [], (err, plans) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch plans' });
    res.json(plans);
  });
});

app.get('/api/admin/subscription-plans/:id', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.get('SELECT * FROM subscription_plans WHERE id = ?', [req.params.id], (err, plan) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch plan' });
    if (!plan) return res.status(404).json({ error: 'Plan not found' });
    res.json(plan);
  });
});

app.post('/api/admin/subscription-plans', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { name, price, applications_limit, opportunities_limit, duration_days, description } = req.body;
  db.run(
    'INSERT INTO subscription_plans (name, price, applications_limit, opportunities_limit, duration_days, description) VALUES (?, ?, ?, ?, ?, ?)',
    [name, price, applications_limit, opportunities_limit, duration_days, description],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to create plan' });
      res.json({ id: this.lastID, message: 'Plan created successfully' });
    }
  );
});

app.put('/api/admin/subscription-plans/:id', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { name, price, applications_limit, opportunities_limit, duration_days, description } = req.body;
  db.run(
    'UPDATE subscription_plans SET name = ?, price = ?, applications_limit = ?, opportunities_limit = ?, duration_days = ?, description = ? WHERE id = ?',
    [name, price, applications_limit, opportunities_limit, duration_days, description, req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update plan' });
      if (this.changes === 0) return res.status(404).json({ error: 'Plan not found' });
      res.json({ message: 'Plan updated successfully' });
    }
  );
});

app.delete('/api/admin/subscription-plans/:id', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.run('DELETE FROM subscription_plans WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete plan' });
    if (this.changes === 0) return res.status(404).json({ error: 'Plan not found' });
    res.json({ message: 'Plan deleted successfully' });
  });
});

// --- Admin CRUD for Deleting Any Application ---
app.delete('/api/applications/:id', authenticateToken, (req, res) => {
  const applicationId = req.params.id;
  // Admin can delete any application, otherwise only the trainee who applied or the clinic owner can delete
  let query = 'DELETE FROM applications WHERE id = ?';
  let params = [applicationId];
  if (req.user.userType !== 'admin') {
    // Only allow if trainee owns or clinic owns the opportunity
    // (for simplicity, only admin can use this endpoint for now)
    return res.status(403).json({ error: 'Not authorized' });
  }
  db.run(query, params, function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete application' });
    if (this.changes === 0) return res.status(404).json({ error: 'Application not found' });
    res.json({ message: 'Application deleted successfully' });
  });
});

// --- Admin CRUD for Deleting Any Review ---
app.delete('/api/clinic/:clinicId/review/:reviewId', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const reviewId = req.params.reviewId;
  db.run('DELETE FROM clinic_reviews WHERE id = ?', [reviewId], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete review' });
    res.json({ message: 'Review deleted successfully' });
  });
});

// --- Admin CRUD for Deleting Any Photo ---
app.delete('/api/clinic/photos/:photoId', authenticateToken, (req, res) => {
  const photoId = req.params.photoId;
  db.get('SELECT * FROM clinic_photos WHERE id = ?', [photoId], (err, photo) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!photo) return res.status(404).json({ error: 'Photo not found' });
    if (photo.clinic_id !== req.user.id && req.user.userType !== 'admin') return res.status(403).json({ error: 'Not authorized' });
    db.run('DELETE FROM clinic_photos WHERE id = ?', [photoId], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete photo' });
      try { require('fs').unlinkSync(photo.photo_path); } catch (e) {}
      res.json({ message: 'Photo deleted successfully' });
    });
  });
});

// --- Admin CRUD for Deleting Any Trainee or Clinic Profile ---
app.delete('/api/admin/trainee/:userId', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const userId = req.params.userId;
  db.run('DELETE FROM trainee_profiles WHERE user_id = ?', [userId], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete trainee profile' });
    db.run('DELETE FROM users WHERE id = ?', [userId], function(err2) {
      if (err2) return res.status(500).json({ error: 'Failed to delete user account' });
      res.json({ message: 'Trainee account and profile deleted successfully' });
    });
  });
});

app.delete('/api/admin/clinic/:userId', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const userId = req.params.userId;
  db.run('DELETE FROM clinic_profiles WHERE user_id = ?', [userId], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete clinic profile' });
    db.run('DELETE FROM users WHERE id = ?', [userId], function(err2) {
      if (err2) return res.status(500).json({ error: 'Failed to delete user account' });
      res.json({ message: 'Clinic account and profile deleted successfully' });
    });
  });
});

// --- Admin: Assign subscription plan to user ---
app.post('/api/admin/assign-subscription', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { user_id, plan_id } = req.body;
  db.get('SELECT * FROM subscription_plans WHERE id = ?', [plan_id], (err, plan) => {
    if (err || !plan) return res.status(400).json({ error: 'Invalid plan' });
    const expiresAt = new Date(Date.now() + plan.duration_days * 24 * 60 * 60 * 1000).toISOString();
    db.run(
      'INSERT INTO subscriptions (user_id, plan_type, applications_limit, opportunities_limit, expires_at) VALUES (?, ?, ?, ?, ?)',
      [user_id, plan.name, plan.applications_limit, plan.opportunities_limit, expiresAt],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to assign subscription' });
        res.json({ id: this.lastID, message: 'Subscription assigned' });
      }
    );
    sendEmail(req.user.email, 'Subscription Activated', 'Your subscription to PLAN_NAME is now active!');
    sendEmail('alphaanimica@gmail.com', 'New Subscription Assigned', 'User EMAIL was assigned PLAN_NAME.');
  });
});

// --- Admin: View user subscriptions ---
app.get('/api/admin/user/:id/subscriptions', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.all('SELECT * FROM subscriptions WHERE user_id = ? ORDER BY expires_at DESC', [req.params.id], (err, subs) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch subscriptions' });
    res.json(subs);
  });
});

// --- Admin: Simulate payment for a subscription (demo/manual) ---
app.post('/api/admin/simulate-payment', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  // For demo, just log and return success
  const { user_id, plan_id, amount } = req.body;
  // In real app, would record payment in a payments table
  res.json({ message: `Simulated payment of ${amount} for user ${user_id} and plan ${plan_id}` });
});

// --- Admin: Record a payment for a user/plan ---
app.post('/api/admin/record-payment', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { user_id, plan_id, amount, method, status, reference } = req.body;
  db.run(
    'INSERT INTO payments (user_id, plan_id, amount, method, status, reference) VALUES (?, ?, ?, ?, ?, ?)',
    [user_id, plan_id, amount, method, status, reference],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to record payment' });
      res.json({ id: this.lastID, message: 'Payment recorded' });
    }
  );
  sendEmail(req.user.email, 'Payment Received', 'Your payment of $AMOUNT for PLAN_NAME was received.');
  sendEmail('alphaanimica@gmail.com', 'New Payment', 'User EMAIL paid $AMOUNT for PLAN_NAME.');
});

// --- Admin: Get all payments for a user ---
app.get('/api/admin/user/:id/payments', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.all('SELECT * FROM payments WHERE user_id = ? ORDER BY paid_at DESC', [req.params.id], (err, payments) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch payments' });
    res.json(payments);
  });
});

// --- Admin: Get all payments ---
app.get('/api/admin/payments', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.all('SELECT * FROM payments ORDER BY paid_at DESC', [], (err, payments) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch payments' });
    res.json(payments);
  });
});

// --- User: Get own subscriptions ---
app.get('/api/user/subscriptions', authenticateToken, (req, res) => {
  db.all('SELECT * FROM subscriptions WHERE user_id = ? ORDER BY expires_at DESC', [req.user.id], (err, subs) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch subscriptions' });
    res.json(subs);
  });
});
// --- User: Get own payments ---
app.get('/api/user/payments', authenticateToken, (req, res) => {
  db.all('SELECT * FROM payments WHERE user_id = ? ORDER BY paid_at DESC', [req.user.id], (err, payments) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch payments' });
    res.json(payments);
  });
});

// --- Stripe: Create Checkout Session for Subscription Plan ---
app.post('/api/stripe/create-checkout-session', authenticateToken, async (req, res) => {
  const { plan_id } = req.body;
  db.get('SELECT * FROM subscription_plans WHERE id = ?', [plan_id], async (err, plan) => {
    if (err || !plan) return res.status(400).json({ error: 'Invalid plan' });
    try {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        mode: 'payment',
        line_items: [{
          price_data: {
            currency: 'usd',
            product_data: { name: plan.name, description: plan.description },
            unit_amount: Math.round(plan.price * 100),
          },
          quantity: 1,
        }],
        customer_email: req.user.email,
        success_url: 'http://localhost:3000/dashboard?payment=success',
        cancel_url: 'http://localhost:3000/dashboard?payment=cancel',
        metadata: { user_id: req.user.id, plan_id: plan.id }
      });
      res.json({ url: session.url });
    } catch (e) {
      res.status(500).json({ error: 'Stripe error', details: e.message });
    }
  });
});

// --- Admin: Subscription stats ---
app.get('/api/admin/stats/subscriptions', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.all('SELECT plan_type, COUNT(*) as count FROM subscriptions GROUP BY plan_type', [], (err, byPlan) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch stats' });
    db.get('SELECT COUNT(*) as total FROM subscriptions', [], (err, total) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch stats' });
      db.get('SELECT COUNT(*) as active FROM subscriptions WHERE expires_at > CURRENT_TIMESTAMP', [], (err, active) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch stats' });
        res.json({ total: total.total, active: active.active, byPlan });
      });
    });
  });
});
// --- Admin: Payment stats ---
app.get('/api/admin/stats/payments', authenticateToken, (req, res) => {
  if (req.user.userType !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.all('SELECT strftime("%Y-%m", paid_at) as month, SUM(amount) as total FROM payments GROUP BY month', [], (err, byMonth) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch stats' });
    db.get('SELECT SUM(amount) as total FROM payments', [], (err, total) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch stats' });
      db.all('SELECT plan_id, SUM(amount) as total FROM payments GROUP BY plan_id', [], (err, byPlan) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch stats' });
        res.json({ total: total.total, byMonth, byPlan });
      });
    });
  });
});

// Public endpoint for non-admin users to fetch subscription plans
app.get('/api/subscription-plans', (req, res) => {
  db.all('SELECT * FROM subscription_plans', (err, plans) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch subscription plans' });
    res.json(plans);
  });
});

// User self-assigns a subscription plan
app.post('/api/subscribe', authenticateToken, (req, res) => {
  const user_id = req.user.id;
  const { plan_id } = req.body;
  db.get('SELECT * FROM subscription_plans WHERE id = ?', [plan_id], (err, plan) => {
    if (err || !plan) return res.status(400).json({ error: 'Invalid plan' });
    const expiresAt = new Date(Date.now() + plan.duration_days * 24 * 60 * 60 * 1000).toISOString();
    db.run(
      'INSERT INTO subscriptions (user_id, plan_type, applications_limit, opportunities_limit, expires_at) VALUES (?, ?, ?, ?, ?)',
      [user_id, plan.name, plan.applications_limit, plan.opportunities_limit, expiresAt],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to assign subscription' });
        res.json({ id: this.lastID, message: 'Subscription assigned' });
      }
    );
    // Optionally send confirmation email here
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 