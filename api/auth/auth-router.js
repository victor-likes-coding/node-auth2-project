const router = require('express').Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require('../secrets'); // use this secret!
const { add } = require('../users/users-model');

router.post('/register', validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  const { username, password } = req.body;
  const { role_name } = req;
  try {
    const hash = bcrypt.hashSync(password, 8);
    const user = await add({ username, password: hash, role_name });
    res.status(201).json(user);
  } catch (err) {
    next(err);
  }
});

router.post('/login', checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

  const { user } = req;
  if (bcrypt.compareSync(req.body.password, user.password)) {
    const token = jwt.sign(
      {
        subject: user.user_id,
        username: user.username,
        role_name: user.role_name,
      },
      JWT_SECRET,
      {
        expiresIn: '1d',
      }
    );
    res.json({
      message: `${user.username} is back!`,
      token,
    });
  } else {
    next({ status: 401, message: 'Invalid credentials' });
  }
});

module.exports = router;
