const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt'); // For password hashing
const jwt = require('jsonwebtoken'); // For JWT authentication
require('dotenv').config(); // Load environment variables from .env file
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key'; // IMPORTANT: Use a strong, random key in production!

console.log('DATABASE_URL:', process.env.DATABASE_URL);


// Middleware

// --- PostgreSQL Setup ---
const pgPool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// --- PostgreSQL Table Creation (clean version, dependency order) ---
pgPool.connect()
    .then(() => {
        console.log('Connected to the PostgreSQL database.');

        // Create tables in the correct dependency order
        return pgPool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
        `);
    })
    .then(() => {
        console.log('Users table checked/created.');
        return pgPool.query(`
            CREATE TABLE IF NOT EXISTS posts (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                categories TEXT,
                author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                createdAt TEXT NOT NULL,
                updatedAt TEXT
            );
        `);
    })
    .then(() => {
        console.log('Posts table checked/created.');
        return pgPool.query(`
            CREATE TABLE IF NOT EXISTS comments (
                id SERIAL PRIMARY KEY,
                post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
                author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                createdAt TEXT NOT NULL
            );
        `);
    })
    .then(() => {
        console.log('Comments table checked/created.');
        return pgPool.query(`
            CREATE TABLE IF NOT EXISTS post_likes (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
                PRIMARY KEY (user_id, post_id)
            );
        `);
    })
    .then(() => {
        console.log('Post Likes table checked/created.');
    })
    .catch(err => {
        console.error('PostgreSQL init error:', err);
    });
app.use(bodyParser.json());
app.use(cors()); // Enable CORS for all routes

// --- Database Setup ---
// Use pgPool as the PostgreSQL client.
const db = pgPool;

// --- Authentication Middleware (JWT-based) ---
const authenticateToken = (req, res, next) => {
    // Get auth header value
    const authHeader = req.headers['authorization'];
    // Check if authHeader is undefined
    if (typeof authHeader !== 'undefined') {
        // Format is "Bearer TOKEN"
        const token = authHeader.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'Unauthorized: No token provided.' });
        }

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                // Token is invalid or expired
                return res.status(403).json({ message: 'Forbidden: Invalid or expired token.' });
            }
            req.userId = user.id; // Attach user ID from token payload to request
            next();
        });
    } else {
        // No authorization header
        res.status(401).json({ message: 'Unauthorized: No authorization header.' });
    }
};

// --- User Routes ---

// Register a new user
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Username, email, and password are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10); // Hash the password
        const result = await db.query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id",
            [username, email, hashedPassword]
        );
        const userId = result.rows[0].id;
        const token = jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '1h' });
        res.status(201).json({
            message: 'User registered successfully',
            userId: userId,
            username: username,
            token: token
        });
    } catch (err) {
        if (err.code === '23505') { // Unique violation
            return res.status(409).json({ message: 'Username or email already exists' });
        }
        console.error('Error registering user:', err.message);
        res.status(500).json({ message: 'Internal server error during registration.' });
    }
});

// User login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    db.get("SELECT id, username, password FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) {
            console.error('Error logging in:', err.message);
            return res.status(500).json({ message: 'Error logging in' });
        }
        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        try {
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ message: 'Invalid username or password' });
            }

            const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
            res.status(200).json({
                message: 'Login successful',
                userId: user.id,
                username: user.username,
                token: token
            });
        } catch (compareErr) {
            console.error('Error comparing passwords:', compareErr);
            res.status(500).json({ message: 'Internal server error during login.' });
        }
    });
});

// --- Blog Post Routes (CRUD operations using SQLite) ---

// Helper function to get like count for a post
const getLikeCount = (postId) => {
    return new Promise((resolve, reject) => {
        db.get("SELECT COUNT(*) AS likes FROM post_likes WHERE post_id = ?", [postId], (err, row) => {
            if (err) {
                reject(err);
            } else {
                resolve(row.likes);
            }
        });
    });
};

// GET all blog posts with author usernames and like counts
app.get('/posts', async (req, res) => {
    const { search, category } = req.query;
    let query = `SELECT p.id, p.title, p.content, p.categories, p.createdAt, p.updatedAt, u.username AS author, u.id AS author_id
                 FROM posts p
                 JOIN users u ON p.author_id = u.id`;
    let params = [];
    let whereClauses = [];

    if (search) {
        whereClauses.push('(p.title LIKE ? OR p.content LIKE ?)');
        params.push(`%${search}%`, `%${search}%`);
    }
    if (category) {
        whereClauses.push('p.categories LIKE ?');
        params.push(`%${category}%`);
    }

    if (whereClauses.length > 0) {
        query += ` WHERE ${whereClauses.join(' AND ')}`;
    }

    query += ` ORDER BY p.createdAt DESC`;

    db.all(query, params, async (err, rows) => {
        if (err) {
            console.error('Error fetching posts:', err.message);
            return res.status(500).json({ message: 'Error fetching posts' });
        }
        // Fetch like counts for each post
        const postsWithLikes = await Promise.all(rows.map(async (post) => {
            const likes = await getLikeCount(post.id);
            return { ...post, likes };
        }));
        res.status(200).json(postsWithLikes);
    });
});

// GET a single blog post by ID with author username and like count
app.get('/posts/:id', async (req, res) => {
    const { id } = req.params;
    const query = `SELECT p.id, p.title, p.content, p.categories, p.createdAt, p.updatedAt, u.username AS author, u.id AS author_id
                   FROM posts p
                   JOIN users u ON p.author_id = u.id
                   WHERE p.id = ?`;
    db.get(query, [id], async (err, row) => {
        if (err) {
            console.error(`Error fetching post ${id}:`, err.message);
            return res.status(500).json({ message: 'Error fetching post' });
        }
        if (row) {
            const likes = await getLikeCount(row.id);
            res.status(200).json({ ...row, likes });
        } else {
            res.status(404).json({ message: 'Post not found' });
        }
    });
});

// CREATE a new blog post
app.post('/posts', authenticateToken, (req, res) => {
    const { title, content, categories } = req.body;
    const author_id = req.userId; // Get author_id from authenticated token

    if (!title || !content) {
        return res.status(400).json({ message: 'Title and content are required' });
    }

    const createdAt = new Date().toISOString();

    db.run("INSERT INTO posts (title, content, categories, author_id, createdAt) VALUES (?, ?, ?, ?, ?)",
        [title, content, categories || '', author_id, createdAt],
        function(err) {
            if (err) {
                console.error('Error creating post:', err.message);
                return res.status(500).json({ message: 'Error creating post' });
            }
            res.status(201).json({
                message: 'Post created successfully',
                id: this.lastID,
                title,
                content,
                categories: categories || '',
                likes: 0, // Initial likes is 0
                author_id,
                createdAt
            });
        }
    );
});

// UPDATE an existing blog post
app.put('/posts/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { title, content, categories } = req.body;
    const userIdFromToken = req.userId; // User ID from authenticated token

    if (!title && !content && !categories) {
        return res.status(400).json({ message: 'At least title, content, or categories is required for update' });
    }

    const updatedAt = new Date().toISOString();
    let fields = [];
    let params = [];

    if (title !== undefined) {
        fields.push('title = ?');
        params.push(title);
    }
    if (content !== undefined) {
        fields.push('content = ?');
        params.push(content);
    }
    if (categories !== undefined) {
        fields.push('categories = ?');
        params.push(categories);
    }

    fields.push('updatedAt = ?');
    params.push(updatedAt);

    // Ensure the user updating the post is the author of the post
    params.push(id);
    params.push(userIdFromToken);

    const query = `UPDATE posts SET ${fields.join(', ')} WHERE id = ? AND author_id = ?`;

    db.run(query, params, function(err) {
        if (err) {
            console.error(`Error updating post ${id}:`, err.message);
            return res.status(500).json({ message: 'Error updating post' });
        }
        if (this.changes === 0) {
            return res.status(403).json({ message: 'Post not found or you are not authorized to update this post.' });
        }
        res.status(200).json({ message: 'Post updated successfully', postId: id, changes: this.changes });
    });
});

// DELETE a blog post
app.delete('/posts/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const userIdFromToken = req.userId; // User ID from authenticated token

    // Ensure the user deleting the post is the author of the post
    db.run("DELETE FROM posts WHERE id = ? AND author_id = ?", [id, userIdFromToken], function(err) {
        if (err) {
            console.error(`Error deleting post ${id}:`, err.message);
            return res.status(500).json({ message: 'Error deleting post' });
        }
        if (this.changes === 0) {
            return res.status(403).json({ message: 'Post not found or you are not authorized to delete this post.' });
        }
        res.status(204).send(); // 204 No Content for successful deletion
    });
});

// --- Like/Unlike Post Routes ---

// Like a post
app.post('/posts/:id/like', authenticateToken, (req, res) => {
    const { id: postId } = req.params;
    const userId = req.userId; // User ID from authenticated token

    // Check if user has already liked this post
    db.get("SELECT * FROM post_likes WHERE user_id = ? AND post_id = ?", [userId, postId], (err, row) => {
        if (err) {
            console.error('Error checking like status:', err.message);
            return res.status(500).json({ message: 'Internal server error.' });
        }
        if (row) {
            return res.status(409).json({ message: 'You have already liked this post.' });
        }

        // Add like to post_likes table
        db.run("INSERT INTO post_likes (user_id, post_id) VALUES (?, ?)", [userId, postId], function(err) {
            if (err) {
                console.error(`Error liking post ${postId}:`, err.message);
                return res.status(500).json({ message: 'Error liking post' });
            }
            if (this.changes === 0) {
                 // This case should ideally not be hit if the row check passed and no DB error.
                return res.status(404).json({ message: 'Post not found or could not record like.' });
            }
            res.status(200).json({ message: 'Post liked successfully', postId: postId });
        });
    });
});

// Unlike a post
app.post('/posts/:id/unlike', authenticateToken, (req, res) => {
    const { id: postId } = req.params;
    const userId = req.userId; // User ID from authenticated token

    // Remove like from post_likes table
    db.run("DELETE FROM post_likes WHERE user_id = ? AND post_id = ?", [userId, postId], function(err) {
        if (err) {
            console.error(`Error unliking post ${postId}:`, err.message);
            return res.status(500).json({ message: 'Error unliking post' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ message: 'Like not found or you have not liked this post.' });
        }
        res.status(200).json({ message: 'Post unliked successfully', postId: postId });
    });
});


// --- Comment Routes ---

// GET comments for a specific post with author usernames
app.get('/posts/:postId/comments', (req, res) => {
    const { postId } = req.params;
    const query = `SELECT c.id, c.content, c.createdAt, u.username AS author, u.id AS author_id
                   FROM comments c
                   JOIN users u ON c.author_id = u.id
                   WHERE c.post_id = ?
                   ORDER BY c.createdAt ASC`;
    db.all(query, [postId], (err, rows) => {
        if (err) {
            console.error(`Error fetching comments for post ${postId}:`, err.message);
            return res.status(500).json({ message: 'Error fetching comments' });
        }
        res.status(200).json(rows);
    });
});

// ADD a comment to a post
app.post('/posts/:postId/comments', authenticateToken, (req, res) => {
    const { postId } = req.params;
    const { content } = req.body;
    const author_id = req.userId; // Get author_id from authenticated token

    if (!content) {
        return res.status(400).json({ message: 'Comment content is required' });
    }

    const createdAt = new Date().toISOString();

    db.run("INSERT INTO comments (post_id, author_id, content, createdAt) VALUES (?, ?, ?, ?)",
        [postId, author_id, content, createdAt],
        function(err) {
            if (err) {
                console.error('Error adding comment:', err.message);
                return res.status(500).json({ message: 'Error adding comment' });
            }
            res.status(201).json({
                message: 'Comment added successfully',
                id: this.lastID,
                post_id: postId,
                author_id,
                content,
                createdAt
            });
        }
    );
});

// DELETE a comment (only by author)
app.delete('/comments/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const userIdFromToken = req.userId; // User ID from authenticated token

    // Ensure the user deleting the comment is the author of the comment
    db.run("DELETE FROM comments WHERE id = ? AND author_id = ?", [id, userIdFromToken], function(err) {
        if (err) {
            console.error(`Error deleting comment ${id}:`, err.message);
            return res.status(500).json({ message: 'Error deleting comment' });
        }
        if (this.changes === 0) {
            return res.status(403).json({ message: 'Comment not found or you are not authorized to delete this comment.' });
        }
        res.status(204).send(); // 204 No Content for successful deletion
    });
});


// Start the server
app.listen(port, () => {
    console.log(`Tech Logs Backend listening at http://localhost:${port}`);
    console.log('Database file: blog.db');
});

// Close the database connection when the app closes
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err.message);
        }
        console.log('Database connection closed.');
        process.exit(0);
    });
});
