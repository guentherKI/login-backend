const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const http = require('http');
const { WebSocketServer } = require('ws');

const app = express();
const port = process.env.PORT || 3001;

app.use(cors());
app.use(bodyParser.json());

// In-memory user store (for demonstration purposes)
const users = [];
const messages = [];
const blacklistedTokens = [];
const SECRET_KEY = 'your_secret_key'; // In a real app, use an environment variable
const passwordResetTokens = new Map();

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);
  if (blacklistedTokens.includes(token)) return res.sendStatus(403);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  const userExists = users.find(user => user.username === username);
  if (userExists) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { username, password: hashedPassword };
  users.push(newUser);

  console.log('Users:', users);

  res.status(201).json({ message: 'User registered successfully' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  const user = users.find(user => user.username === username);
  if (!user) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  const isPasswordCorrect = await bcrypt.compare(password, user.password);
  if (!isPasswordCorrect) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });

  res.json({ token });
});

app.post('/api/logout', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    blacklistedTokens.push(token);
  }

  res.json({ message: 'Logged out successfully' });
});

app.get('/api/profile', authenticateToken, (req, res) => {
  const user = users.find(user => user.username === req.user.username);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }
  // Exclude password from the user object
  const { password, ...profile } = user;
  res.json(profile);
});

app.post('/api/forgot-password', (req, res) => {
  const { username } = req.body;
  const user = users.find(user => user.username === username);

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  // In a real app, you would send an email with a reset link
  const resetToken = jwt.sign({ username }, SECRET_KEY, { expiresIn: '15m' });
  passwordResetTokens.set(resetToken, username);

  console.log(`Password reset token for ${username}: ${resetToken}`);
  res.json({ message: 'Password reset token generated. Check the server console.' });
});

app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ message: 'Token and new password are required' });
  }

  if (!passwordResetTokens.has(token)) {
    return res.status(400).json({ message: 'Invalid or expired token' });
  }

  const username = passwordResetTokens.get(token);
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);
  user.password = hashedPassword;
  passwordResetTokens.delete(token);

  res.json({ message: 'Password has been reset successfully' });
});


const server = http.createServer(app);
const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
  console.log('Client connected');

  ws.on('message', (message) => {
    const data = JSON.parse(message);
    console.log('received: %s', data);

    if (data.type === 'message') {
      const newMessage = { user: data.user, text: data.text, timestamp: new Date() };
      messages.push(newMessage);
      wss.clients.forEach((client) => {
        if (client.readyState === ws.OPEN) {
          client.send(JSON.stringify(newMessage));
        }
      });
    }
  });

  ws.on('close', () => {
    console.log('Client disconnected');
  });
});

server.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
