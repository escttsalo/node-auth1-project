const router = require('express').Router()
const User = require('../users/users-model')
const bcrypt = require('bcryptjs')
const { checkUsernameFree, checkPasswordLength, checkUsernameExists } = require('./auth-middleware')
// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!

router.post('/register', checkUsernameFree, checkPasswordLength, async (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, 8);
  const newUser = await User.add({
    username: username,
    password: hash,
  })

  res.status(201).json({
    user_id: newUser.user_id,
    username: newUser.username, 
  })

})

router.post('/login', checkUsernameExists, async (req, res) => {
  const { username, password } = req.body
  const user = await User.findBy({username}).first()
  if (user && bcrypt.compareSync(password, user.password)){
    req.session.user = user
    res.status(200).json({
      message: `Welcome ${username}`
    })
  } else {
    res.status(401).json({
      message: 'Invalid credentials'
    })
  }
})

router.get('/logout', (req, res) => {
  if (req.session && req.session.user) {
    const { username } = req.session.user
    req.session.destroy(err => {
      if (err) {
        res.json({
          message: `leaving so soon, ${username}?`
        });
      } else {
        res.json({
          message: `${username} has been logged out`
        });
      }
    });
  } else {
    res.json({
      message: `there's no session taking place here`
    });
  }
});
/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;