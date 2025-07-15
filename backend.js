// ✅ Tech Logs Backend - Fully Migrated to PostgreSQL

const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { Pool } = require("pg");
const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";

app.use(
  cors({
    origin: '*',
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
console.log("DATABASE_URL:", process.env.DATABASE_URL);

const pgPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

pgPool
  .connect()
  .then(() => {
    console.log("Connected to the PostgreSQL database.");
    return pgPool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
    `);
  })
  .then(() =>
    pgPool.query(`
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      categories TEXT,
      author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      createdAt TEXT NOT NULL,
      updatedAt TEXT
    );
  `)
  )
  .then(() =>
    pgPool.query(`
    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
      author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      createdAt TEXT NOT NULL
    );
  `)
  )
  .then(() =>
    pgPool.query(`
    CREATE TABLE IF NOT EXISTS post_likes (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
      PRIMARY KEY (user_id, post_id)
    );
  `)
  )
  .then(() => console.log("All tables checked/created."))
  .catch((err) => console.error("PostgreSQL init error:", err));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token)
    return res
      .status(401)
      .json({ message: "Unauthorized: No token provided." });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err)
      return res
        .status(403)
        .json({ message: "Forbidden: Invalid or expired token." });
    req.userId = user.id;
    next();
  });
};

app.post("/register", async (req, res) => {
  console.log("Request body for register:", req.body); 
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res
      .status(400)
      .json({ message: "Username, email, and password are required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pgPool.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id",
      [username, email, hashedPassword]
    );
    const token = jwt.sign({ id: result.rows[0].id }, JWT_SECRET, {
      expiresIn: "1h",
    });
    res
      .status(201)
      .json({
        message: "User registered successfully",
        userId: result.rows[0].id,
        username,
        token,
      });
  } catch (err) {
    if (err.code === "23505")
      return res
        .status(409)
        .json({ message: "Username or email already exists" });
    console.error("Register error:", err.message);
    res
      .status(500)
      .json({ message: "Internal server error during registration." });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res
      .status(400)
      .json({ message: "Username and password are required" });

  try {
    const result = await pgPool.query(
      "SELECT id, username, password FROM users WHERE username = $1",
      [username]
    );
    const user = result.rows[0];
    if (!user)
      return res.status(401).json({ message: "Invalid username or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid username or password" });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });
    res
      .status(200)
      .json({
        message: "Login successful",
        userId: user.id,
        username: user.username,
        token,
      });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ message: "Internal server error during login." });
  }
});

app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const result = await pgPool.query(
      "SELECT id, username FROM users WHERE id = $1",
      [req.userId]
    );
    if (!result.rows[0])
      return res.status(404).json({ message: "User not found" });
    res.json({ userId: result.rows[0].id, username: result.rows[0].username });
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).json({ message: "Error retrieving profile" });
  }
});

app.get("/posts/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const post = await pgPool.query(
      `
      SELECT p.*, u.username AS author
      FROM posts p
      JOIN users u ON p.author_id = u.id
      WHERE p.id = $1
    `,
      [id]
    );
    if (!post.rows[0])
      return res.status(404).json({ message: "Post not found" });

    const likeCount = await pgPool.query(
      "SELECT COUNT(*) FROM post_likes WHERE post_id = $1",
      [id]
    );
    res.json({ ...post.rows[0], likes: parseInt(likeCount.rows[0].count) });
  } catch (err) {
    console.error("Fetch single post error:", err.message);
    res.status(500).json({ message: "Error fetching post" });
  }
});

app.post("/posts", authenticateToken, async (req, res) => {
  const { title, content, categories } = req.body;
  const createdAt = new Date().toISOString();

  try {
    const result = await pgPool.query(
      `
      INSERT INTO posts (title, content, categories, author_id, createdAt)
      VALUES ($1, $2, $3, $4, $5) RETURNING *
    `,
      [title, content, categories || "", req.userId, createdAt]
    );

    res.status(201).json({ ...result.rows[0], likes: 0 });
  } catch (err) {
    console.error("Create post error:", err.message);
    res.status(500).json({ message: "Error creating post" });
  }
});

app.put("/posts/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, content, categories } = req.body;
  const updatedAt = new Date().toISOString();
  let fields = [],
    params = [],
    i = 1;

  if (title !== undefined) {
    fields.push(`title = $${i++}`);
    params.push(title);
  }
  if (content !== undefined) {
    fields.push(`content = $${i++}`);
    params.push(content);
  }
  if (categories !== undefined) {
    fields.push(`categories = $${i++}`);
    params.push(categories);
  }
  fields.push(`updatedAt = $${i}`);
  params.push(updatedAt);
  params.push(id, req.userId);

  const query = `UPDATE posts SET ${fields.join(", ")} WHERE id = $${
    i + 1
  } AND author_id = $${i + 2}`;
  try {
    const result = await pgPool.query(query, params);
    if (result.rowCount === 0)
      return res
        .status(403)
        .json({ message: "Not authorized or post not found" });
    res.json({ message: "Post updated successfully" });
  } catch (err) {
    console.error("Update post error:", err.message);
    res.status(500).json({ message: "Error updating post" });
  }
});

app.delete("/posts/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pgPool.query(
      "DELETE FROM posts WHERE id = $1 AND author_id = $2",
      [id, req.userId]
    );
    if (result.rowCount === 0)
      return res
        .status(403)
        .json({ message: "Not authorized or post not found" });
    res.sendStatus(204);
  } catch (err) {
    console.error("Delete post error:", err.message);
    res.status(500).json({ message: "Error deleting post" });
  }
});

app.post("/posts/:id/like", authenticateToken, async (req, res) => {
  const postId = req.params.id;
  try {
    const existing = await pgPool.query(
      "SELECT * FROM post_likes WHERE user_id = $1 AND post_id = $2",
      [req.userId, postId]
    );
    if (existing.rows.length > 0)
      return res.status(409).json({ message: "You already liked this post." });
    await pgPool.query(
      "INSERT INTO post_likes (user_id, post_id) VALUES ($1, $2)",
      [req.userId, postId]
    );
    res.json({ message: "Post liked successfully" });
  } catch (err) {
    console.error("Like post error:", err.message);
    res.status(500).json({ message: "Error liking post" });
  }
});

app.post("/posts/:id/unlike", authenticateToken, async (req, res) => {
  const postId = req.params.id;
  try {
    const result = await pgPool.query(
      "DELETE FROM post_likes WHERE user_id = $1 AND post_id = $2",
      [req.userId, postId]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ message: "You have not liked this post." });
    res.json({ message: "Post unliked successfully" });
  } catch (err) {
    console.error("Unlike post error:", err.message);
    res.status(500).json({ message: "Error unliking post" });
  }
});

app.get("/posts", async (req, res) => {
  try {
    const result = await pgPool.query(`
      SELECT p.id, p.title, p.content, p.categories, p.createdAt, p.updatedAt,
             u.username AS author
      FROM posts p
      JOIN users u ON p.author_id = u.id
      ORDER BY p.createdAt DESC
    `);

    const postsWithLikes = await Promise.all(
      result.rows.map(async (post) => {
        const likeResult = await pgPool.query(
          "SELECT COUNT(*) FROM post_likes WHERE post_id = $1",
          [post.id]
        );
        const likes = parseInt(likeResult.rows[0].count || "0");
        return { ...post, likes };
      })
    );

    res.status(200).json(postsWithLikes);
  } catch (err) {
    console.error("Error fetching posts:", err.message);
    res.status(500).json({ message: "Error fetching posts" });
  }
});

app.get("/posts/:postId/comments", async (req, res) => {
  const { postId } = req.params;
  try {
    const result = await pgPool.query(
      `
      SELECT c.id, c.content, c.createdAt, u.username AS author, u.id AS author_id
      FROM comments c
      JOIN users u ON c.author_id = u.id
      WHERE c.post_id = $1 ORDER BY c.createdAt ASC
    `,
      [postId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Fetch comments error:", err.message);
    res.status(500).json({ message: "Error fetching comments" });
  }
});

app.post("/posts/:postId/comments", authenticateToken, async (req, res) => {
  const { postId } = req.params;
  const { content } = req.body;
  const createdAt = new Date().toISOString();

  try {
    const result = await pgPool.query(
      `
      INSERT INTO comments (post_id, author_id, content, createdAt)
      VALUES ($1, $2, $3, $4) RETURNING *
    `,
      [postId, req.userId, content, createdAt]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Add comment error:", err.message);
    res.status(500).json({ message: "Error adding comment" });
  }
});

app.delete("/comments/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pgPool.query(
      "DELETE FROM comments WHERE id = $1 AND author_id = $2",
      [id, req.userId]
    );
    if (result.rowCount === 0)
      return res
        .status(403)
        .json({ message: "Comment not found or not authorized." });
    res.sendStatus(204);
  } catch (err) {
    console.error("Delete comment error:", err.message);
    res.status(500).json({ message: "Error deleting comment" });
  }
});

app.get("/", (req, res) => {
  res.send("Tech Logs Backend is running ✅");
});

app.listen(port, () => {
  console.log(`Tech Logs Backend listening at http://localhost:${port}`);
});
// Export the pool for testing purposes
