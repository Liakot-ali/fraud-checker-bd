const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Relational SQLite Database [cite: 56, 114]
const db = new sqlite3.Database(':memory:', (err) => {
    if (err) console.error(err.message);
    console.log('Connected to the in-memory SQLite database.');
    initializeDatabase();
});

function initializeDatabase() {
    // 5.2 Proposed Database Model Tables [cite: 115]
    db.serialize(() => {
        db.run(`CREATE TABLE cheater_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            display_name TEXT,
            normalized_name TEXT,
            profile_status TEXT,
            created_at TEXT,
            updated_at TEXT
        )`);

        db.run(`CREATE TABLE identifiers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER,
            identifier_type TEXT,
            identifier_value TEXT,
            normalized_value TEXT,
            is_primary INTEGER,
            FOREIGN KEY(profile_id) REFERENCES cheater_profiles(id)
        )`);

        db.run(`CREATE TABLE fraud_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER,
            reporter_name TEXT,
            reporter_visibility TEXT,
            scam_type TEXT,
            loss_item TEXT,
            loss_amount REAL,
            description TEXT,
            gd_number TEXT,
            address TEXT,
            status TEXT,
            submitted_at TEXT,
            approved_at TEXT,
            rejected_at TEXT,
            FOREIGN KEY(profile_id) REFERENCES cheater_profiles(id)
        )`);

        db.run(`CREATE TABLE event_phones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            phone_number TEXT,
            normalized_phone TEXT,
            FOREIGN KEY(event_id) REFERENCES fraud_events(id)
        )`);

        db.run(`CREATE TABLE audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_type TEXT,
            actor_id TEXT,
            action TEXT,
            metadata TEXT,
            created_at TEXT
        )`);

        // Seed default Admin user for testing [cite: 123]
        db.run(`CREATE TABLE admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password_hash TEXT,
            role TEXT
        )`);
        
        db.run(`INSERT INTO admin_users (username, password_hash, role) VALUES ('admin', 'admin123', 'superuser')`);
    });
}

// Helper: Text Normalization [cite: 125]
const normalize = (text) => text ? text.toLowerCase().replace(/[^a-z0-9]/g, '') : '';

// --- PUBLIC API INTERFACES --- [cite: 139]

// GET /search?q=... Public Search Engine [cite: 140]
app.get('/api/search', (req, requireRes) => {
    const query = req.query.q || '';
    const normQuery = normalize(query);

    const sql = `
        SELECT DISTINCT cp.* FROM cheater_profiles cp
        LEFT JOIN identifiers id ON cp.id = id.profile_id
        WHERE cp.normalized_name LIKE ? 
           OR id.normalized_value LIKE ?
    `;
    const params = [`%${normQuery}%`, `%${normQuery}%`];

    db.all(sql, params, (err, rows) => {
        if (err) return requireRes.status(500).json({ error: err.message });
        requireRes.json(rows);
    });
});

// GET /profiles/{id} Fetch Public Profile Details [cite: 141]
app.get('/api/profiles/:id', (req, res) => {
    const profileId = req.params.id;
    
    db.get(`SELECT * FROM cheater_profiles WHERE id = ?`, [profileId], (err, profile) => {
        if (err || !profile) return res.status(404).json({ error: "Profile not found" });

        db.all(`SELECT * FROM fraud_events WHERE profile_id = ? AND status = 'approved'`, [profileId], (err, events) => {
            db.all(`SELECT identifier_type, identifier_value FROM identifiers WHERE profile_id = ?`, [profileId], (err, idents) => {
                res.json({ profile, events, identifiers: idents });
            });
        });
    });
});

// POST /events Submit Fraud Event (No Login Required) [cite: 14, 142]
app.post('/api/events', (req, res) => {
    const { name, phone, identifier, scam_type, loss_item, loss_amount, description, gd_number, address, reporter_name, reporter_visibility } = req.body;
    
    // Mandatory Validation Guardrails [cite: 84]
    if (!name || !phone || !identifier || !scam_type || !loss_item || !description) {
        return res.status(400).json({ error: "Missing required functional tracking parameters." });
    }

    const timestamp = new Date().toISOString();
    const sql = `INSERT INTO fraud_events (reporter_name, reporter_visibility, scam_type, loss_item, loss_amount, description, gd_number, address, status, submitted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`;
    
    db.run(sql, [reporter_name || 'Anonymous', reporter_visibility, scam_type, loss_item, loss_amount || 0, description, gd_number || '', address || '', timestamp], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        
        const eventId = this.lastID;
        db.run(`INSERT INTO event_phones (event_id, phone_number, normalized_phone) VALUES (?, ?, ?)`, [phone, normalize(phone), eventId]);
        db.run(`INSERT INTO identifiers (profile_id, identifier_type, identifier_value, normalized_value, is_primary) VALUES (NULL, 'Initial Submission Field', ?, ?, 0)`, [identifier, normalize(identifier)]);

        res.json({ message: "Fraud allegation submitted successfully to review queue.", eventId });
    });
});

// --- SECURE ADMINISTRATIVE OPERATIONS --- [cite: 29]

// POST /admin/login Authentication [cite: 143]
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM admin_users WHERE username = ? AND password_hash = ?`, [username, password], (err, row) => {
        if (row) res.json({ success: true, token: "mock-valid-jwt-token" });
        else res.status(401).json({ success: false, error: "Invalid credentials" });
    });
});

// GET /admin/moderation-queue [cite: 144]
app.get('/api/admin/moderation-queue', (req, res) => {
    db.all(`SELECT * FROM fraud_events WHERE status = 'pending'`, [], (err, rows) => {
        res.json(rows);
    });
});

// PATCH /admin/events/{id}/action [cite: 145]
app.patch('/api/admin/events/:id/:action', (req, res) => {
    const { id, action } = req.params;
    const allowedActions = ['approve', 'reject'];
    if (!allowedActions.includes(action)) return res.status(400).json({ error: "Action disallowed" });

    const status = action === 'approve' ? 'approved' : 'rejected';
    const timestamp = new Date().toISOString();

    db.run(`UPDATE fraud_events SET status = ?, approved_at = ? WHERE id = ?`, [status, timestamp, id], function(err) {
        if (err) return res.status(500).json({ error: err.message });

        if (status === 'approved') {
            // High Confidence Profile Identifier Merge Logic Pipeline [cite: 91]
            db.get(`SELECT * FROM fraud_events WHERE id = ?`, [id], (err, event) => {
                db.get(`SELECT phone_number FROM event_phones WHERE event_id = ?`, [id], (err, pRow) => {
                    const normPhone = normalize(pRow.phone_number);
                    
                    db.get(`SELECT profile_id FROM identifiers WHERE normalized_value = ? AND profile_id IS NOT NULL`, [normPhone], (err, match) => {
                        if (match) {
                            // Update Existing Profile Context [cite: 90]
                            db.run(`UPDATE fraud_events SET profile_id = ? WHERE id = ?`, [match.profile_id, id]);
                            res.json({ message: "Record approved and appended to existing matching profile profile." });
                        } else {
                            // Provision Distinct Consolidated Profile Document Identity [cite: 90]
                            db.run(`INSERT INTO cheater_profiles (display_name, normalized_name, profile_status, created_at) VALUES (?, ?, 'verified', ?)`, [event.scam_type, normalize(event.scam_type), timestamp], function() {
                                const newProfileId = this.lastID;
                                db.run(`UPDATE fraud_events SET profile_id = ? WHERE id = ?`, [newProfileId, id]);
                                db.run(`INSERT INTO identifiers (profile_id, identifier_type, identifier_value, normalized_value, is_primary) VALUES (?, 'phone', ?, ?, 1)`, [newProfileId, pRow.phone_number, normPhone]);
                                res.json({ message: "Record approved and new profile established." });
                            });
                        }
                    });
                });
            });
        } else {
            res.json({ message: "Submission rejected and flagged away from public search indices." });
        }
    });
});

app.listen(PORT, () => console.log(`Fraud-checker-bd operational framework running on port ${PORT}`));