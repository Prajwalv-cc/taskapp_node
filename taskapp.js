const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect('mongodb://localhost/task_management_app', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log(err));

// Task Model
const Task = mongoose.model('Task', {
  title: String,
  description: String,
  userId: String
});

// User Model
const User = mongoose.model('User', {
  username: String,
  passwordHash: String
});

app.use(bodyParser.json());

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send({ auth: false, message: 'No token provided.' });

  jwt.verify(token, 'secret_key', (err, decoded) => {
    if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });

    // If everything is good, save to request for use in other routes
    req.userId = decoded.id;
    next();
  });
};

// Create User
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const passwordHash = bcrypt.hashSync(password, 8);
  const user = new User({ username, passwordHash });
  await user.save();
  const token = jwt.sign({ id: user._id }, 'secret_key', { expiresIn: 86400 }); // Expires in 24 hours
  res.status(200).send({ auth: true, token });
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).send('User not found.');

  const isValidPassword = bcrypt.compareSync(password, user.passwordHash);
  if (!isValidPassword) return res.status(401).send({ auth: false, token: null });

  const token = jwt.sign({ id: user._id }, 'secret_key', { expiresIn: 86400 }); // Expires in 24 hours
  res.status(200).send({ auth: true, token });
});

// Create Task
app.post('/tasks', verifyToken, async (req, res) => {
  const { title, description } = req.body;
  const task = new Task({ title, description, userId: req.userId });
  await task.save();
  res.status(200).send(task);
});

// Update Task
app.put('/tasks/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { title, description } = req.body;
  await Task.findByIdAndUpdate(id, { title, description });
  res.status(200).send('Task updated successfully.');
});

// Delete Task
app.delete('/tasks/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  await Task.findByIdAndDelete(id);
  res.status(200).send('Task deleted successfully.');
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
