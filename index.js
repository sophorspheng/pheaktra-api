const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;
const secret = 'jajowej2398723uy7676&^%&^@#YHH*YHWQ873Y9';

app.use(bodyParser.json());

// MySQL Connection
const db = mysql.createConnection({
    host: 'b8pfpb7dqm6bufgemlas-mysql.services.clever-cloud.com',
    user: 'uzhmenmyq98jajqv',
    password: 'KH4jgcsg4ibMxpgD7O5',
    database: 'b8pfpb7dqm6bufgemlas',
    port: '20690'
});

db.connect(err => {
    if (err) throw err;
    console.log('MySQL Connected...');
});
app.get('/',(req,res)=>{
  res.send("Hello")
})
// Register User
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Please provide all required fields' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    db.query(sql, [username, email, hashedPassword], (err, result) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                return res.status(400).json({ message: 'Email already exists' });
            }
            throw err;
        }
        res.status(201).json({ message: 'User registered successfully' });
    });
});

// Login User
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Please provide email and password' });
    }

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], async (err, results) => {
        if (err) throw err;

        if (results.length === 0) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const user = results[0];

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, secret, {
            expiresIn: '1h',
        });

        res.json({ token });
    });
});

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Protected Route Example
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: `Hello ${req.user.role}!`, user: req.user });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
