'use strict';

const {
  Router
} = require('express');
const router = Router();

const User = require('./../models/user');
const bcryptjs = require('bcrypt');

router.get('/', (req, res, next) => {
  res.render('index', {
    title: 'Authentication Practice'
  });
});

//Iteration 1 - register 
router.get('/sign-up', (req, res, next) => {
  res.render('sign-up');
});

router.post('/sign-up', (req, res, next) => {
  const {
    username,
    password
  } = req.body;
  bcryptjs
    .hash(password, 10)
    .then(hash => {
      return User.create({
        username,
        passwordHash: hash
      });
    })
    .then(user => {
      console.log('Created user', user);
      req.session.user = user._id;
      res.redirect('/');
    })
    .catch(error => {
      next(error);
    });
});

//Iteration 2 - sign in

router.get('/sign-in', (req, res, next) => {
  res.render('sign-in');
});

router.post('/sign-in', (req, res, next) => {
  let userId;
  const {
    username,
    password
  } = req.body;
  // Find a user with an email that corresponds to the one
  // inserted by the user in the sign in form
  User.findOne({
      username
    })
    .then(user => {
      if (!user) {
        // If no user was found, return a rejection with an error
        // that will be sent to the error handler at the end of the promise chain
        return Promise.reject(new Error("There's no user with that username."));
      } else {
        // If there is an user,
        // save their ID to an auxiliary variable
        userId = user._id;
        // Compare the password with the salt + hash stored in the user document
        return bcryptjs.compare(password, user.passwordHash);
      }
    })
    .then(result => {
      if (result) {
        // If they match, the user has successfully been signed up
        req.session.user = userId;
        res.redirect('/');
      } else {
        // If they don't match, reject with an error message
        return Promise.reject(new Error('Wrong password.'));
      }
    })
    .catch(error => {
      next(error);
    });
});

// Import custom middleware that stops unauthenticated users
// from visiting a route meant for authenticated users only
const routeGuard = require('./../middleware/route-guard');

router.get('/private', routeGuard, (req, res, next) => {
  res.render('private');
});
router.get('/main', routeGuard, (req, res, next) => {
  res.render('main');
});
router.get('/profile', (req, res, next) => {
  res.render('profile');
});

module.exports = router;