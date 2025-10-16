// server.js
import express from 'express';
import mongoose from 'mongoose';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import fs from 'fs';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

const app = express();
const port = process.env.PORT || 3000;

// Fix for ES Modules (__dirname in Node.js)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(__dirname)); // Serve static files

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/participant', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('✅ MongoDB connected...'))
    .catch(err => console.log('❌ MongoDB connection error:', err));

// Schemas
const userSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, required: true, unique: true },
    country: String,
    password: { type: String, required: true },
    termsAccepted: Boolean,
});

const projectSchema = new mongoose.Schema({
    name: String,
    description: String,
    github: { type: String, unique: true, sparse: true },
    video: String,
    ppt: String,
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});

const teamSchema = new mongoose.Schema({
    name: String,
    members: [{
        name: String,
        email: String,
        role: String,
    }],
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});

const inviteSchema = new mongoose.Schema({
    token: { type: String, required: true, unique: true },
    name: String,
    email: { type: String, required: true },
    role: String,
    team: { type: mongoose.Schema.Types.ObjectId, ref: 'Team', required: true },
    used: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
});

// Models
const User = mongoose.model('User', userSchema);
const Project = mongoose.model('Project', projectSchema);
const Team = mongoose.model('Team', teamSchema);
const Invite = mongoose.model('Invite', inviteSchema);

// File Upload Setup (PPT)
const pptDir = path.join(__dirname, 'uploads/ppt');
if (!fs.existsSync(pptDir)) fs.mkdirSync(pptDir, { recursive: true });

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, pptDir),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname);
    },
});

const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = [
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        ];
        cb(null, allowedTypes.includes(file.mimetype));
    },
    limits: { fileSize: 20 * 1024 * 1024 },
});

app.use('/uploads/ppt', express.static(path.join(__dirname, 'uploads/ppt')));

// Config
const SMTP_USER = process.env.SMTP_USER || 'legendrpgamer@gmail.com';
const SMTP_PASS = process.env.SMTP_PASS || 'zxcticeqhsbtxpch';
const JWT_SECRET = process.env.JWT_SECRET || 'secretkey';

// Mail Transporter
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
});

transporter.verify((err) => {
    if (err) console.warn("⚠️ Nodemailer verify failed:", err.message);
    else console.log("✅ Nodemailer transporter ready");
});

// Routes
// Register User
app.post("/register", async (req, res) => {
    const { firstName, lastName, email, country, password, confirmPassword, terms } = req.body;
    if (!password || !confirmPassword) return res.status(400).json({ error: 'Password required' });
    if (password.trim() !== confirmPassword.trim()) return res.status(400).json({ error: 'Passwords do not match' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            firstName, lastName, email, country,
            password: hashedPassword, termsAccepted: !!terms,
        });

        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        if (err.code === 11000) return res.status(400).json({ error: 'Email already registered' });
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// Login
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: 'User not found' });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// Auth Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.userId = user.id;
        next();
    });
}

// Upload Project
app.post('/api/projects', upload.single('ppt'), authenticateToken, async (req, res) => {
    try {
        const { name, description, github, video } = req.body;
        if (!name) return res.status(400).json({ error: 'Project name required' });

        const normalizedGithub = normalizeGithubLink(github);

        // Only check for duplicates if a github link is provided
        if (normalizedGithub) {
            const existing = await Project.findOne({ github: normalizedGithub }).collation({ locale: 'en', strength: 2 });
            if (existing) {
                // Only send duplicate alert if a project with the same github link exists
                return res.status(400).json({ error: 'GitHub link already used' });
            }
        }

        const pptPath = req.file ? `/uploads/ppt/${req.file.filename}` : null;

        const project = new Project({
            name,
            description,
            github: normalizedGithub || undefined,
            video,
            ppt: pptPath,
            user: req.userId
        });

        await project.save();
        res.status(201).json({ success: true, project });
    } catch (err) {
        // Only send duplicate alert if MongoDB reports a duplicate key error for github
        if (err.code === 11000 && err.keyPattern && err.keyPattern.github) {
            return res.status(400).json({ error: 'GitHub link already used' });
        }
        res.status(500).json({ error: 'Project upload failed' });
    }
});

// Get Projects
app.get('/api/projects', authenticateToken, async (req, res) => {
    const projects = await Project.find({ user: req.userId });
    res.json(projects);
});

// Get or Create Team
app.get('/api/team', authenticateToken, async (req, res) => {
    let team = await Team.findOne({ owner: req.userId });
    if (!team) {
        const user = await User.findById(req.userId);
        team = new Team({
            name: `${user.firstName || 'My'}'s Team`,
            owner: req.userId,
            members: []
        });
        await team.save();
    }
    res.json(team);
});

// Invite Member
app.post('/api/team/member', authenticateToken, async (req, res) => {
    try {
        const { name, email, role } = req.body;
        if (!email) return res.status(400).json({ error: 'Email required' });

        let team = await Team.findOne({ owner: req.userId });
        if (!team) {
            const user = await User.findById(req.userId);
            team = new Team({ name: `${user.firstName || 'My'}'s Team`, owner: req.userId });
            await team.save();
        }

        const token = crypto.randomBytes(32).toString("hex");
        const invite = new Invite({ token, name, email, role, team: team._id });
        await invite.save();

        const inviteLink = `http://localhost:${port}/team/invite/accept?token=${token}`;
        const mailOptions = {
            from: `"Hackathon Team" <${SMTP_USER}>`,
            to: email,
            subject: "Team Invitation",
            html: `<p>Hello ${name || email},</p>
                   <p>You are invited as <b>${role || 'Member'}</b>.</p>
                   <p><a href="${inviteLink}">Accept Invitation</a></p>`
        };

        await transporter.sendMail(mailOptions);
        res.json({ success: true, message: 'Invitation sent!' });
    } catch (err) {
        console.error("Invite error:", err);
        res.status(500).json({ error: 'Failed to invite member' });
    }
});

// Accept Invite
app.get('/team/invite/accept', async (req, res) => {
    try {
        const { token } = req.query;
        const invite = await Invite.findOne({ token, used: false }).populate('team');
        if (!invite) return res.status(400).send("Invalid or expired invite.");

        invite.team.members.push({
            name: invite.name || invite.email.split('@')[0],
            email: invite.email,
            role: invite.role || 'Member'
        });
        await invite.team.save();
        invite.used = true;
        await invite.save();

        res.send(`<h2>✅ Joined team: ${invite.team.name}</h2>
                  <p>Welcome, ${invite.name || invite.email.split('@')[0]}!</p>`);
    } catch {
        res.status(500).send("Server error while accepting invite");
    }
});

// Remove Member
app.delete('/api/team/member/:memberId', authenticateToken, async (req, res) => {
    const team = await Team.findOne({ owner: req.userId });
    if (!team) return res.status(404).json({ error: 'Team not found' });

    team.members = team.members.filter(m => m._id.toString() !== req.params.memberId);
    await team.save();
    res.json({ success: true, team });
});

// --- Static Routes ---
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "homepage.html")));
app.get("/register", (req, res) => res.sendFile(path.join(__dirname, "register.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/chatroom", (req, res) => res.redirect("http://localhost:5173/login"));

// --- Error Handling ---
app.use((err, req, res, next) => {
    console.error("Unhandled error:", err);
    if (err instanceof multer.MulterError)
        return res.status(400).json({ error: err.message });
    res.status(500).json({ error: 'Internal server error' });
});

// --- Start Server ---
app.listen(port, () => console.log(`🚀 Server running at http://localhost:${port}`));

function normalizeGithubLink(link) {
    return link?.trim().toLowerCase();
}

// --- Ensure Unique Index (case-insensitive) ---
Project.collection.createIndex(
    { github: 1 },
    { unique: true, sparse: true, collation: { locale: 'en', strength: 2 }, name: "github_1" }
).catch(err => {
    if (err.code === 86) {
        console.warn("Index github_1 already exists. If you want to update it, drop it manually in MongoDB.");
    } else {
        console.error("Index creation error:", err);
    }
});

// --- Patch Project Upload Route ---
app.post('/api/projects', upload.single('ppt'), authenticateToken, async (req, res) => {
    try {
        const { name, description, github, video } = req.body;
        if (!name) return res.status(400).json({ error: 'Project name required' });

        const normalizedGithub = normalizeGithubLink(github);

        // Only check for duplicates if a github link is provided
        if (normalizedGithub) {
            const existing = await Project.findOne({ github: normalizedGithub }).collation({ locale: 'en', strength: 2 });
            if (existing) {
                // Only send duplicate alert if a project with the same github link exists
                return res.status(400).json({ error: 'GitHub link already used' });
            }
        }

        const pptPath = req.file ? `/uploads/ppt/${req.file.filename}` : null;

        const project = new Project({
            name,
            description,
            github: normalizedGithub || undefined,
            video,
            ppt: pptPath,
            user: req.userId
        });

        await project.save();
        res.status(201).json({ success: true, project });
    }
    catch (err) {
        // Only send duplicate alert if MongoDB reports a duplicate key error for github
        if (err.code === 11000 && err.keyPattern && err.keyPattern.github) {
            return res.status(400).json({ error: 'GitHub link already used' });
        }
        res.status(500).json({ error: 'Project upload failed' });
    }
});
