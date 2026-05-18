const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || 'fraud_checker_db';

let db = null;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Helper: Text Normalization
const normalize = (text) => text ? text.toLowerCase().replace(/[^a-z0-9]/g, '') : '';

// Initialize MongoDB Connection
async function connectToDatabase() {
    try {
        const client = new MongoClient(MONGODB_URI);
        await client.connect();
        console.log('✓ Connected to MongoDB Atlas');
        
        db = client.db(DB_NAME);
        await initializeDatabase();
        
        return client;
    } catch (err) {
        console.error('✗ MongoDB Connection Error:', err.message);
        process.exit(1);
    }
}

async function initializeDatabase() {
    try {
        const collections = await db.listCollections().toArray();
        const collectionNames = collections.map(c => c.name);

        // Create collections if they don't exist
        if (!collectionNames.includes('cheater_profiles')) {
            await db.createCollection('cheater_profiles');
            console.log('✓ Created collection: cheater_profiles');
        }

        if (!collectionNames.includes('identifiers')) {
            await db.createCollection('identifiers');
            console.log('✓ Created collection: identifiers');
        }

        if (!collectionNames.includes('fraud_events')) {
            await db.createCollection('fraud_events');
            console.log('✓ Created collection: fraud_events');
        }

        if (!collectionNames.includes('event_phones')) {
            await db.createCollection('event_phones');
            console.log('✓ Created collection: event_phones');
        }

        if (!collectionNames.includes('audit_logs')) {
            await db.createCollection('audit_logs');
            console.log('✓ Created collection: audit_logs');
        }

        if (!collectionNames.includes('admin_users')) {
            await db.createCollection('admin_users');
            console.log('✓ Created collection: admin_users');
        }

        // Seed default admin user if not exists
        const adminCount = await db.collection('admin_users').countDocuments({ username: 'admin' });
        if (adminCount === 0) {
            await db.collection('admin_users').insertOne({
                username: 'admin',
                password_hash: 'admin123',
                role: 'superuser',
                created_at: new Date().toISOString()
            });
            console.log('✓ Seeded admin user (admin/admin123)');
        }

        // Seed sample fraudster profile if collection is empty
        const profileCount = await db.collection('cheater_profiles').countDocuments();
        if (profileCount === 0) {
            // Sample profile
            const sampleProfile = await db.collection('cheater_profiles').insertOne({
                display_name: 'Sample Fraudster',
                normalized_name: normalize('Sample Fraudster'),
                profile_status: 'verified',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            });

            // Sample identifier
            const samplePhone = '+1-234-567-8900';
            await db.collection('identifiers').insertOne({
                profile_id: sampleProfile.insertedId,
                identifier_type: 'phone',
                identifier_value: samplePhone,
                normalized_value: normalize(samplePhone),
                is_primary: true
            });

            // Sample fraud event
            await db.collection('fraud_events').insertOne({
                profile_id: sampleProfile.insertedId,
                reporter_name: 'Test Reporter',
                reporter_visibility: 'anonymous',
                scam_type: 'Online Payment Fraud',
                loss_item: 'Money Transfer',
                loss_amount: 5000,
                description: 'Sample fraud case for demonstration purposes',
                gd_number: 'GD001',
                address: 'Sample Address',
                status: 'approved',
                submitted_at: new Date().toISOString(),
                approved_at: new Date().toISOString()
            });

            console.log('✓ Seeded sample fraudster profile with test data');
        }

        console.log(`✓ Database initialized: ${DB_NAME}`);
    } catch (err) {
        console.error('Database initialization error:', err.message);
        throw err;
    }
}

// --- PUBLIC API INTERFACES ---

// GET /search?q=... Public Search Engine - Search across approved events and profiles
app.get('/api/search', async (req, res) => {
    try {
        const query = req.query.q || '';
        const normQuery = normalize(query);

        const fraudEvents = db.collection('fraud_events');
        const eventPhones = db.collection('event_phones');
        const identifiersCollection = db.collection('identifiers');
        const cheaterProfiles = db.collection('cheater_profiles');

        // Search approved fraud events by various fields
        const eventMatches = await fraudEvents.find({
            status: 'approved',
            $or: [
                { description: new RegExp(query, 'i') },
                { scam_type: new RegExp(query, 'i') },
                { loss_item: new RegExp(query, 'i') },
                { address: new RegExp(query, 'i') },
                { reporter_name: new RegExp(query, 'i') }
            ]
        }).toArray();

        // Also search by phone numbers
        const phoneMatches = await eventPhones.find({
            normalized_phone: new RegExp(normQuery)
        }).project({ event_id: 1 }).toArray();

        const phoneEventIds = new Set(phoneMatches.map(p => p.event_id.toString()));
        const allEventIds = new Set(eventMatches.map(e => e._id.toString()));

        // Get events matched by phone
        if (phoneMatches.length > 0) {
            const phoneEvents = await fraudEvents.find({
                _id: { $in: phoneMatches.map(p => p.event_id) },
                status: 'approved'
            }).toArray();
            phoneEvents.forEach(e => allEventIds.add(e._id.toString()));
        }

        // Fetch detailed event data with phone and profile info
        const uniqueEventIds = Array.from(allEventIds).map(id => new ObjectId(id));
        const detailedEvents = await fraudEvents.find({
            _id: { $in: uniqueEventIds }
        }).toArray();

        // Enrich events with phone and profile data
        const resultsWithDetails = await Promise.all(
            detailedEvents.map(async (event) => {
                const phones = await eventPhones.find({ event_id: event._id }).toArray();
                let profile = null;
                if (event.profile_id) {
                    profile = await cheaterProfiles.findOne({ _id: event.profile_id });
                }
                return {
                    ...event,
                    phones: phones.map(p => p.phone_number),
                    profile_name: profile?.display_name || 'Unknown',
                    profile_id: profile?._id
                };
            })
        );

        res.json(resultsWithDetails);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /profiles/{id} Fetch Public Profile Details
app.get('/api/profiles/:id', async (req, res) => {
    try {
        const profileId = new ObjectId(req.params.id);
        const cheaterProfiles = db.collection('cheater_profiles');
        const fraudEvents = db.collection('fraud_events');
        const identifiersCollection = db.collection('identifiers');

        const profile = await cheaterProfiles.findOne({ _id: profileId });
        if (!profile) {
            return res.status(404).json({ error: "Profile not found" });
        }

        const events = await fraudEvents.find({
            profile_id: profileId,
            status: 'approved'
        }).toArray();

        const idents = await identifiersCollection.find({
            profile_id: profileId
        }).project({ identifier_type: 1, identifier_value: 1 }).toArray();

        res.json({ profile, events, identifiers: idents });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /events Submit Fraud Event (No Login Required)
app.post('/api/events', async (req, res) => {
    try {
        const { name, phone, identifier, scam_type, loss_item, loss_amount, description, gd_number, address, reporter_name, reporter_visibility } = req.body;

        // Mandatory Validation Guardrails
        if (!name || !phone || !identifier || !scam_type || !loss_item || !description) {
            return res.status(400).json({ error: "Missing required functional tracking parameters." });
        }

        const timestamp = new Date().toISOString();
        const fraudEvents = db.collection('fraud_events');
        const eventPhones = db.collection('event_phones');
        const identifiersCollection = db.collection('identifiers');

        // Insert fraud event
        const eventResult = await fraudEvents.insertOne({
            profile_id: null,
            reporter_name: reporter_name || 'Anonymous',
            reporter_visibility,
            scam_type,
            loss_item,
            loss_amount: loss_amount || 0,
            description,
            gd_number: gd_number || '',
            address: address || '',
            status: 'pending',
            submitted_at: timestamp,
            approved_at: null,
            rejected_at: null
        });

        const eventId = eventResult.insertedId;

        // Insert event phone
        await eventPhones.insertOne({
            event_id: eventId,
            phone_number: phone,
            normalized_phone: normalize(phone)
        });

        // Insert identifier placeholder
        await identifiersCollection.insertOne({
            profile_id: null,
            identifier_type: 'Initial Submission Field',
            identifier_value: identifier,
            normalized_value: normalize(identifier),
            is_primary: false
        });

        res.json({ message: "Fraud allegation submitted successfully to review queue.", eventId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- SECURE ADMINISTRATIVE OPERATIONS ---

// POST /admin/login Authentication
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const adminUsers = db.collection('admin_users');

        const admin = await adminUsers.findOne({ username, password_hash: password });
        if (admin) {
            res.json({ success: true, token: "mock-valid-jwt-token" });
        } else {
            res.status(401).json({ success: false, error: "Invalid credentials" });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /admin/moderation-queue
app.get('/api/admin/moderation-queue', async (req, res) => {
    try {
        const fraudEvents = db.collection('fraud_events');
        const events = await fraudEvents.find({ status: 'pending' }).toArray();
        res.json(events);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /admin/events/:id/details - Get full event details with related data
app.get('/api/admin/events/:id/details', async (req, res) => {
    try {
        const eventId = new ObjectId(req.params.id);
        const fraudEvents = db.collection('fraud_events');
        const eventPhones = db.collection('event_phones');
        const identifiersCollection = db.collection('identifiers');
        const cheaterProfiles = db.collection('cheater_profiles');

        const event = await fraudEvents.findOne({ _id: eventId });
        if (!event) {
            return res.status(404).json({ error: "Event not found" });
        }

        // Get phone numbers associated with this event
        const phoneData = await eventPhones.find({ event_id: eventId }).toArray();

        // Get profile information if linked
        let profile = null;
        if (event.profile_id) {
            profile = await cheaterProfiles.findOne({ _id: event.profile_id });
        }

        // Get all identifiers from initial submission
        const identifiers = await identifiersCollection.find({
            $or: [
                { profile_id: event.profile_id },
                { identifier_type: 'Initial Submission Field' }
            ]
        }).toArray();

        res.json({
            event,
            phones: phoneData,
            profile,
            identifiers
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// PATCH /admin/events/{id}/action
app.patch('/api/admin/events/:id/:action', async (req, res) => {
    try {
        const { id, action } = req.params;
        const allowedActions = ['approve', 'reject'];
        
        if (!allowedActions.includes(action)) {
            return res.status(400).json({ error: "Action disallowed" });
        }

        const eventId = new ObjectId(id);
        const status = action === 'approve' ? 'approved' : 'rejected';
        const timestamp = new Date().toISOString();

        const fraudEvents = db.collection('fraud_events');
        const eventPhones = db.collection('event_phones');
        const identifiersCollection = db.collection('identifiers');
        const cheaterProfiles = db.collection('cheater_profiles');

        // Update event status
        await fraudEvents.updateOne(
            { _id: eventId },
            {
                $set: {
                    status,
                    [action === 'approve' ? 'approved_at' : 'rejected_at']: timestamp
                }
            }
        );

        if (status === 'approved') {
            // High Confidence Profile Identifier Merge Logic Pipeline
            const event = await fraudEvents.findOne({ _id: eventId });
            const phoneData = await eventPhones.findOne({ event_id: eventId });

            if (phoneData) {
                const normPhone = normalize(phoneData.phone_number);

                // Check if matching profile exists by phone number
                const matchingIdentifier = await identifiersCollection.findOne({
                    normalized_value: normPhone,
                    profile_id: { $ne: null }
                });

                if (matchingIdentifier) {
                    // Update Existing Profile Context - just link the event
                    await fraudEvents.updateOne(
                        { _id: eventId },
                        { $set: { profile_id: matchingIdentifier.profile_id } }
                    );
                    res.json({ message: "Record approved and appended to existing matching profile." });
                } else {
                    // Provision Distinct Consolidated Profile Document Identity
                    // Use the submitted name from the event or scam_type as fallback
                    const fraudsterName = event.reporter_name && event.reporter_name !== 'Anonymous' 
                        ? event.reporter_name 
                        : event.scam_type || 'Unidentified Fraudster';

                    const newProfile = await cheaterProfiles.insertOne({
                        display_name: fraudsterName,
                        normalized_name: normalize(fraudsterName),
                        profile_status: 'verified',
                        created_at: timestamp,
                        updated_at: timestamp
                    });

                    const newProfileId = newProfile.insertedId;

                    // Update event to link to new profile
                    await fraudEvents.updateOne(
                        { _id: eventId },
                        { $set: { profile_id: newProfileId } }
                    );

                    // Insert primary phone identifier
                    await identifiersCollection.insertOne({
                        profile_id: newProfileId,
                        identifier_type: 'phone',
                        identifier_value: phoneData.phone_number,
                        normalized_value: normPhone,
                        is_primary: true
                    });

                    res.json({ message: "Record approved and new profile established." });
                }
            } else {
                res.json({ message: "Record approved but no phone data found." });
            }
        } else {
            res.json({ message: "Submission rejected and flagged away from public search indices." });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Start server
connectToDatabase().then(() => {
    app.listen(PORT, () => console.log(`✓ Fraud-checker-bd operational framework running on port ${PORT}`));
});