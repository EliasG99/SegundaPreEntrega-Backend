// Imports

import { Router } from 'express';
import { usersModel } from '../dao/models/users.model.js';
import { createHash, validatePassword } from '../utils.js';
import passport from 'passport';

// Definitions

export const router = Router()

// Middlewares

function auth (req, res, next) { // Middleware to check if a user is authenticated
  if (!req.session.user){
    res.setHeader('Content-Type', 'application/json');
    return res.status(401).json({error: 'Not authorized. There are no logged in users, go to /login'})
  }
  next();
}

// Methods

router.get('/github', passport.authenticate('github', {}) ,async (req, res) => {
  return res.redirect('/products')
});

router.get('/callbackGithub', passport.authenticate('github', {failureRedirect:'/api/sessions/loginError'}) ,async (req, res) => {
  req.session.user = req.user;
  console.log('Req Session on callbackGithub: ', req.session.user);
  return res.redirect('/products')

});

router.get('/loginError', (req, res) => {
  return res.redirect('/login?error=Unexpected error in login')
});

router.post('/login', passport.authenticate('login', {failureRedirect: '/api/sessions/loginError'}), async (req,res) => {
  req.session.user={ // We create a user session that stores the user that logged in
    name: req.user.name,
    email: req.user.email,
    role: req.user.role
  } 
  return res.redirect('/products')
  
})

router.get('/signupError', (req, res) => {
  return res.redirect('/signup?error=Error during signup');
});

router.post('/signup', passport.authenticate('signup', {failureRedirect: '/api/sessions/signupError'}), async (req,res) => {
  let {email} = req.body;
  return res.redirect(`/login?message=Account ${email} created`);
})

router.get('/data', auth, async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  try {
    res.status(200).json({
      message: 'Success'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/logout', async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  try {
    req.session.destroy();
    return res.redirect(`/login?message=You have logged out`);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});





