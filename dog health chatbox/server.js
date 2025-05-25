// Import required modules
const http = require('http');
const fs = require('node:fs');
const path = require('node:path');
const dotenv = require('dotenv');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { MongoClient, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const imageService = require('./services/imageService');

// Load environment variables
dotenv.config();

// MongoDB connection
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const dbName = 'pet_health_assistant';
let db;

async function connectToDb() {
    try {
        const client = await MongoClient.connect(mongoUri);
        db = client.db(dbName);
        console.log('Connected to MongoDB');
        
        // Create indexes
        await db.collection('users').createIndex({ email: 1 }, { unique: true });
        await db.collection('pets').createIndex({ userId: 1 });
        await db.collection('health_records').createIndex({ petId: 1 });
        await db.collection('vet_visits').createIndex({ userId: 1 });
    } catch (error) {
        console.error('MongoDB connection error:', error);
        process.exit(1);
    }
}

connectToDb();

// Rate limiting configuration
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});

// Authentication middleware
async function authenticateToken(req) {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) return null;
        
        const user = jwt.verify(token, process.env.JWT_SECRET);
        const dbUser = await db.collection('users').findOne({ _id: ObjectId(user.id) });
        return dbUser;
    } catch (error) {
        console.error('Auth error:', error);
        return null;
    }
}

// Create the server
const server = http.createServer(async (req, res) => {
    // Apply security headers
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'", 'cdn.tailwindcss.com', 'cdnjs.cloudflare.com'],
                styleSrc: ["'self'", "'unsafe-inline'", 'cdn.tailwindcss.com', 'cdnjs.cloudflare.com'],
                imgSrc: ["'self'", 'data:', 'blob:'],
                connectSrc: ["'self'", 'api-inference.huggingface.co', 'nominatim.openstreetmap.org', 'overpass-api.de']
            }
        }
    });

    // Apply rate limiting
    limiter(req, res, async () => {
        // Log each request
        console.log('Request:', req.method, req.url);

        // Set CORS headers
        res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGINS || '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

        // Handle OPTIONS requests
        if (req.method === 'OPTIONS') {
            res.writeHead(204);
            res.end();
            return;
        }

        // API endpoints
        if (req.url.startsWith('/api/')) {
            await handleApiRequest(req, res);
            return;
        }

        // Handle static file requests
        handleStaticFiles(req, res);
    });
});

// API request handler
async function handleApiRequest(req, res) {
    try {
        // Auth endpoints
        if (req.url === '/api/auth/register' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                try {
                    const { name, email, password } = JSON.parse(body);
                    
                    // Validate input
                    if (!name || !email || !password) {
                        res.writeHead(400);
                        res.end(JSON.stringify({ error: 'Missing required fields' }));
                        return;
                    }

                    // Hash password
                    const hashedPassword = await bcrypt.hash(password, 10);
                    
                    // Create user
                    const result = await db.collection('users').insertOne({
                        name,
                        email,
                        password: hashedPassword,
                        createdAt: new Date()
                    });

                    // Generate token
                    const token = jwt.sign({ id: result.insertedId }, process.env.JWT_SECRET);
                    
                    res.writeHead(201, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ token }));
                } catch (error) {
                    console.error('Registration error:', error);
                    res.writeHead(500);
                    res.end(JSON.stringify({ error: 'Registration failed' }));
                }
            });
            return;
        }

        if (req.url === '/api/auth/login' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                try {
                    const { email, password } = JSON.parse(body);
                    
                    // Find user
                    const user = await db.collection('users').findOne({ email });
                    if (!user) {
                        res.writeHead(401);
                        res.end(JSON.stringify({ error: 'Invalid credentials' }));
                        return;
                    }

                    // Check password
                    const validPassword = await bcrypt.compare(password, user.password);
                    if (!validPassword) {
                        res.writeHead(401);
                        res.end(JSON.stringify({ error: 'Invalid credentials' }));
                        return;
                    }

                    // Generate token
                    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
                    
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ token }));
                } catch (error) {
                    console.error('Login error:', error);
                    res.writeHead(500);
                    res.end(JSON.stringify({ error: 'Login failed' }));
                }
            });
            return;
        }

        // Protected routes - require authentication
        const user = await authenticateToken(req);
        if (!user) {
            res.writeHead(401);
            res.end(JSON.stringify({ error: 'Unauthorized' }));
            return;
        }

        // Chat endpoint
        if (req.url === '/api/chat' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                try {
                    const data = JSON.parse(body);
                    
                    if (!data.message || typeof data.message !== 'string') {
                        res.writeHead(400);
                        res.end(JSON.stringify({ error: 'Invalid input' }));
                        return;
                    }

                    // Save chat history
                    await db.collection('chat_history').insertOne({
                        userId: user._id,
                        message: data.message,
                        timestamp: new Date()
                    });

                    // Call Hugging Face API
                    const response = await fetch('https://api-inference.huggingface.co/models/microsoft/DialoGPT-medium', {
      method: 'POST',
      headers: {
                            'Authorization': `Bearer ${process.env.HUGGING_FACE_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
                            inputs: {
                                text: `As a pet health assistant, please provide advice for: ${data.message}. Remember to be helpful but remind that a vet should be consulted for specific medical advice.`
        }
      })
    });

    if (!response.ok) {
                        throw new Error(`API request failed with status ${response.status}`);
                    }

                    const result = await response.json();
                    
                    // Save bot response
                    await db.collection('chat_history').insertOne({
                        userId: user._id,
                        message: result.generated_text,
                        isBot: true,
                        timestamp: new Date()
                    });

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ reply: result.generated_text }));
                } catch (error) {
                    console.error('Chat error:', error);
                    res.writeHead(500);
                    res.end(JSON.stringify({ error: 'Internal server error' }));
                }
            });
            return;
        }

        // Pet management endpoints
        if (req.url === '/api/pets' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                try {
                    const petData = JSON.parse(body);
                    petData.userId = user._id;
                    petData.createdAt = new Date();
                    
                    const result = await db.collection('pets').insertOne(petData);
                    
                    res.writeHead(201, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ id: result.insertedId }));
                } catch (error) {
                    console.error('Error creating pet:', error);
                    res.writeHead(500);
                    res.end(JSON.stringify({ error: 'Failed to create pet' }));
                }
            });
            return;
        }

        if (req.url === '/api/pets' && req.method === 'GET') {
            try {
                const pets = await db.collection('pets')
                    .find({ userId: user._id })
                    .toArray();
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(pets));
            } catch (error) {
                console.error('Error fetching pets:', error);
                res.writeHead(500);
                res.end(JSON.stringify({ error: 'Failed to fetch pets' }));
            }
            return;
        }

        // Health records endpoints
        if (req.url.startsWith('/api/health-records/') && req.method === 'POST') {
            const petId = req.url.split('/')[3];
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                try {
                    const recordData = JSON.parse(body);
                    recordData.petId = ObjectId(petId);
                    recordData.userId = user._id;
                    recordData.createdAt = new Date();
                    
                    const result = await db.collection('health_records').insertOne(recordData);
                    
                    res.writeHead(201, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ id: result.insertedId }));
                } catch (error) {
                    console.error('Error creating health record:', error);
                    res.writeHead(500);
                    res.end(JSON.stringify({ error: 'Failed to create health record' }));
                }
            });
            return;
        }

        // Add image upload endpoint
        if (req.url === '/api/upload' && req.method === 'POST') {
            await handleImageUpload(req, res);
            return;
        }

        // Default response for unknown endpoints
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'Not found' }));
    } catch (error) {
        console.error('API error:', error);
        res.writeHead(500);
        res.end(JSON.stringify({ error: 'Internal server error' }));
    }
}

// Add image upload route
async function handleImageUpload(req, res) {
    try {
        const uploadMiddleware = imageService.getUploadMiddleware();
        
        uploadMiddleware(req, res, async (err) => {
            if (err) {
                res.writeHead(400);
                res.end(JSON.stringify({ error: err.message }));
                return;
            }

            if (!req.file) {
                res.writeHead(400);
                res.end(JSON.stringify({ error: 'No file uploaded' }));
                return;
            }

            const result = await imageService.processImage(req.file);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.writeHead(500);
        res.end(JSON.stringify({ error: 'Upload failed' }));
    }
}

// Static file handler
function handleStaticFiles(req, res) {
    let filePath = req.url;
    
    // Handle image URLs
    if (filePath.startsWith('/uploads/')) {
        filePath = path.join(__dirname, '..', filePath);
    } else {
        if (filePath === '/') {
            filePath = '/index.html';
        }
        filePath = path.join(__dirname, '..', filePath.replace(/^\//, ''));
    }
    
    // Get file extension
    const ext = path.extname(filePath);
    
    // Map file extensions to content types
    const contentTypes = {
        '.html': 'text/html',
        '.js': 'text/javascript',
        '.css': 'text/css',
        '.json': 'application/json',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.svg': 'image/svg+xml'
    };
    const contentType = contentTypes[ext] || 'text/plain';

    // Read and serve the file
    fs.readFile(filePath, (error, content) => {
        if (error) {
            if (error.code === 'ENOENT') {
                res.writeHead(404);
                res.end('File not found');
            } else {
                res.writeHead(500);
                res.end('Server error: ' + error.code);
            }
        } else {
            // Add cache headers for static files
            const oneYear = 31536000;
            res.writeHead(200, { 
                'Content-Type': contentType,
                'Cache-Control': `public, max-age=${oneYear}`,
                'Expires': new Date(Date.now() + oneYear * 1000).toUTCString()
            });
            res.end(content);
        }
    });
}

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
    console.log('Server root directory:', path.join(__dirname, '..'));
});
