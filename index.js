const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const stripe = require('stripe')('sk_test_51Nw...your_test_key_here...'); // Replace with your Stripe test secret key

const app = express();
const PORT = process.env.PORT || 5000;

// Supabase configuration
const supabaseUrl = 'https://kdxknxeoinwlwgkotfyd.supabase.co';
const supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtkeGtueGVvaW53bHdna290ZnlkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTIwMDIyNTYsImV4cCI6MjA2NzU3ODI1Nn0.ew_cL6Vze3h_VGInS1SyAyBfIRWOMKCiObbuLs19X6k';
const supabase = createClient(supabaseUrl, supabaseKey);

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Helper: get active subscription for user
async function getActiveSubscription(userId) {
  const { data, error } = await supabase
    .from('subscriptions')
    .select('*')
    .eq('user_id', userId)
    .gt('expires_at', new Date().toISOString())
    .order('expires_at', { ascending: false })
    .limit(1);
  
  if (error) throw error;
  return data[0] || null;
}

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, 'your_jwt_secret_here', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

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

// Email configuration
function sendEmail(to, subject, text) {
  // Your email configuration here
  console.log(`Email to ${to}: ${subject} - ${text}`);
}

// --- AUTHENTICATION ENDPOINTS ---

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name, userType } = req.body;
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Insert user
    const { data: user, error } = await supabase
      .from('users')
      .insert([{
        email,
        password: hashedPassword,
        name,
        user_type: userType
      }])
      .select()
      .single();
    
    if (error) {
      if (error.code === '23505') { // Unique constraint violation
            return res.status(400).json({ error: 'Email already exists' });
      }
      throw error;
    }
    
    // Create JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, userType: user.user_type },
      'your_jwt_secret_here',
      { expiresIn: '24h' }
    );
    
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, userType: user.user_type } });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
  const { email, password } = req.body;
  
    // Get user
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();
    
    if (error || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, userType: user.user_type },
      'your_jwt_secret_here',
      { expiresIn: '24h' }
    );
    
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, userType: user.user_type } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// --- PROFILE ENDPOINTS ---

// Get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.user.id)
      .single();
    
    if (error) throw error;
    
    // Get profile based on user type
    if (user.user_type === 'trainee') {
      const { data: profile } = await supabase
        .from('trainee_profiles')
        .select('*')
        .eq('user_id', req.user.id)
        .single();
      user.profile = profile;
    } else if (user.user_type === 'clinic') {
      const { data: profile } = await supabase
        .from('clinic_profiles')
        .select('*')
        .eq('user_id', req.user.id)
        .single();
      user.profile = profile;
    }
    
    res.json(user);
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update trainee profile
app.put('/api/trainee-profile', authenticateToken, upload.single('resume'), async (req, res) => {
  try {
    if (req.user.userType !== 'trainee') {
      return res.status(403).json({ error: 'Trainee only' });
    }
    
    const profileData = {
      user_id: req.user.id,
      phone: req.body.phone,
      location: req.body.location,
      education: req.body.education,
      skills: req.body.skills,
      experience: req.body.experience,
      university_year: req.body.university_year
    };
    
    if (req.file) {
      profileData.resume_path = req.file.filename;
    }
    
    // Upsert profile
    const { data, error } = await supabase
      .from('trainee_profiles')
      .upsert(profileData, { onConflict: 'user_id' })
      .select()
      .single();
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Update clinic profile
app.put('/api/clinic-profile', authenticateToken, upload.single('logo'), async (req, res) => {
  try {
    if (req.user.userType !== 'clinic') {
      return res.status(403).json({ error: 'Clinic only' });
    }
    
    const profileData = {
      user_id: req.user.id,
      clinic_name: req.body.clinic_name,
      phone: req.body.phone,
      address: req.body.address,
      description: req.body.description,
      website: req.body.website
    };
    
    if (req.file) {
      profileData.logo_path = req.file.filename;
    }
    
    // Upsert profile
    const { data, error } = await supabase
      .from('clinic_profiles')
      .upsert(profileData, { onConflict: 'user_id' })
      .select()
      .single();
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// --- OPPORTUNITIES ENDPOINTS ---

// Get all opportunities
app.get('/api/opportunities', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('opportunities')
      .select(`
        *,
        clinic_profiles!inner(
          clinic_name,
          address,
          logo_path
        )
      `)
      .eq('status', 'active')
      .order('created_at', { ascending: false });
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Opportunities fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch opportunities' });
  }
});

// Create opportunity
app.post('/api/opportunities', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'clinic') {
      return res.status(403).json({ error: 'Clinic only' });
    }
    
    // Check subscription limit
    const subscription = await getActiveSubscription(req.user.id);
    if (!subscription || subscription.opportunities_limit <= 0) {
      return res.status(403).json({ error: 'No opportunities remaining in subscription' });
    }
    
    const { data, error } = await supabase
      .from('opportunities')
      .insert([{
        clinic_id: req.user.id,
        title: req.body.title,
        description: req.body.description,
        requirements: req.body.requirements,
        location: req.body.location,
        is_paid: req.body.is_paid,
        salary_range: req.body.salary_range,
        skills_required: req.body.skills_required
      }])
      .select()
      .single();
    
    if (error) throw error;
    
    // Decrement opportunities limit
    await supabase
      .from('subscriptions')
      .update({ opportunities_limit: subscription.opportunities_limit - 1 })
      .eq('id', subscription.id);
    
    res.json(data);
  } catch (error) {
    console.error('Opportunity creation error:', error);
    res.status(500).json({ error: 'Failed to create opportunity' });
  }
});

// --- APPLICATIONS ENDPOINTS ---

// Apply for opportunity
app.post('/api/apply', authenticateToken, upload.single('resume'), async (req, res) => {
  try {
    if (req.user.userType !== 'trainee') {
      return res.status(403).json({ error: 'Trainee only' });
    }
    
    // Check subscription limit
    const subscription = await getActiveSubscription(req.user.id);
    if (!subscription || subscription.applications_limit <= 0) {
      return res.status(403).json({ error: 'No applications remaining in subscription' });
    }
    
    const applicationData = {
      trainee_id: req.user.id,
      opportunity_id: req.body.opportunity_id,
      cover_letter: req.body.cover_letter
    };
    
    if (req.file) {
      applicationData.resume_path = req.file.filename;
    }
    
    const { data, error } = await supabase
      .from('applications')
      .insert([applicationData])
      .select()
      .single();
    
    if (error) throw error;
    
    // Decrement applications limit
    await supabase
      .from('subscriptions')
      .update({ applications_limit: subscription.applications_limit - 1 })
      .eq('id', subscription.id);
    
    res.json(data);
  } catch (error) {
    console.error('Application error:', error);
    res.status(500).json({ error: 'Failed to submit application' });
  }
});

// Get user applications
app.get('/api/applications', authenticateToken, async (req, res) => {
  try {
    let query;
    if (req.user.userType === 'trainee') {
      query = supabase
        .from('applications')
        .select(`
          *,
          opportunities!inner(
            title,
            description,
            clinic_profiles!inner(
              clinic_name
            )
          )
        `)
        .eq('trainee_id', req.user.id);
    } else if (req.user.userType === 'clinic') {
      query = supabase
        .from('applications')
        .select(`
          *,
          opportunities!inner(
            title,
            description
          ),
          trainee_profiles!inner(
            phone,
            location,
            education,
            skills
          )
        `)
        .eq('opportunities.clinic_id', req.user.id);
    }
    
    const { data, error } = await query;
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Applications fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch applications' });
  }
});

// --- SUBSCRIPTION ENDPOINTS ---

// Get subscription plans
app.get('/api/subscription-plans', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('subscription_plans')
      .select('*');
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Subscription plans error:', error);
    res.status(500).json({ error: 'Failed to fetch subscription plans' });
  }
});

// Subscribe to plan
app.post('/api/subscribe', authenticateToken, async (req, res) => {
  try {
    const { plan_id } = req.body;
    
    // Get plan details
    const { data: plan, error: planError } = await supabase
      .from('subscription_plans')
      .select('*')
      .eq('id', plan_id)
      .single();
    
    if (planError || !plan) {
      return res.status(400).json({ error: 'Invalid plan' });
    }
    
    // Calculate expiry date
    const expiresAt = new Date(Date.now() + plan.duration_days * 24 * 60 * 60 * 1000).toISOString();
    
    // Create subscription
    const { data, error } = await supabase
      .from('subscriptions')
      .insert([{
        user_id: req.user.id,
        plan_type: plan.name,
        applications_limit: plan.applications_limit,
        opportunities_limit: plan.opportunities_limit,
        expires_at: expiresAt
      }])
      .select()
      .single();
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Subscription error:', error);
    res.status(500).json({ error: 'Failed to create subscription' });
  }
});

// Get user subscriptions
app.get('/api/user/subscriptions', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('subscriptions')
      .select('*')
      .eq('user_id', req.user.id)
      .order('expires_at', { ascending: false });
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Subscriptions fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch subscriptions' });
  }
});

// --- ADMIN ENDPOINTS ---

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'admin') {
      return res.status(403).json({ error: 'Admin only' });
    }
    
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .order('created_at', { ascending: false });
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Users fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get all opportunities (admin only)
app.get('/api/admin/opportunities', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'admin') {
      return res.status(403).json({ error: 'Admin only' });
    }
    
    const { data, error } = await supabase
      .from('opportunities')
      .select(`
        *,
        clinic_profiles!inner(
          clinic_name
        )
      `)
      .order('created_at', { ascending: false });
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Opportunities fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch opportunities' });
  }
});

// Get all applications (admin only)
app.get('/api/admin/applications', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'admin') {
      return res.status(403).json({ error: 'Admin only' });
    }
    
    const { data, error } = await supabase
      .from('applications')
      .select(`
        *,
        opportunities!inner(
          title,
          clinic_profiles!inner(
            clinic_name
          )
        ),
        trainee_profiles!inner(
          phone,
          location
        )
      `)
      .order('applied_at', { ascending: false });
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Applications fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch applications' });
  }
});

// Get dashboard stats (admin only)
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'admin') {
      return res.status(403).json({ error: 'Admin only' });
    }
    
    // Get counts
    const { count: usersCount } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true });
    
    const { count: opportunitiesCount } = await supabase
      .from('opportunities')
      .select('*', { count: 'exact', head: true });
    
    const { count: applicationsCount } = await supabase
      .from('applications')
      .select('*', { count: 'exact', head: true });
    
    const { count: subscriptionsCount } = await supabase
      .from('subscriptions')
      .select('*', { count: 'exact', head: true });
    
    res.json({
      users: usersCount,
      opportunities: opportunitiesCount,
      applications: applicationsCount,
      subscriptions: subscriptionsCount
    });
  } catch (error) {
    console.error('Stats fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 