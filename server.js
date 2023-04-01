const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const port = 3000;
const secret = 'mysecretkey';

// database of users (in memory for simplicity)
const users = [];

// middleware to parse incoming JSON data
app.use(bodyParser.json());

// signup endpoint
app.post('/auth/signup', (req, res) => {
  const { login, password } = req.body;

  // check if login and password are provided and are strings
  if (!login || !password || typeof login !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: 'Invalid data transfer object' });
  }

  // check if user with the same login already exists
  if (users.some(user => user.login === login)) {
    return res.status(400).json({ message: 'User with this login already exists' });
  }

  // hash password
  const hashedPassword = bcrypt.hashSync(password, 10);

  // create new user
  const user = { id: users.length + 1, login, password: hashedPassword };
  users.push(user);

  return res.status(201).json({ message: 'User created successfully' });
});

// login endpoint
app.post('/auth/login', (req, res) => {
  const { login, password } = req.body;

  // check if login and password are provided and are strings
  if (!login || !password || typeof login !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: 'Invalid data transfer object' });
  }

  // find user by login
  const user = users.find(user => user.login === login);

  // check if user with the login exists
  if (!user) {
    return res.status(403).json({ message: 'Authentication failed' });
  }

  // compare password with the hash
  if (!bcrypt.compareSync(password, user.password)) {
    return res.status(403).json({ message: 'Authentication failed' });
  }

  // generate access token with user id and login in the payload
  const accessToken = jwt.sign({ userId: user.id, login: user.login }, secret, { expiresIn: '1h' });

  return res.status(200).json({ accessToken });
});

app.listen(port, () => console.log(`Server started on port ${port}`));
