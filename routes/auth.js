const bcrypt = require('bcrypt');
const saltRounds = 10; 
const router = require("express").Router();
const User = require('../models/User.model');

//GET /signup
router.get('/signup', (req, res) => {
    res.render('auth/signup');
});

//POST /signup
router.post('/signup', (req, res) => {
    const { username, password } = req.body;

    //Checking if both fields contain data
    if (!username || !password){
        res.render('auth/signup', {errorMessage: 'Please input both username and password'});
        return; 
    }

    //creating a new user (bcrypt for password)
    bcrypt
        .genSalt(saltRounds)
        .then(salt => bcrypt.hash(password, salt))
        .then(hashedPassword => {
            return User.create({
                username,
                password: hashedPassword
            });
        })
        .then(userFromDB => {
            console.log(`New user created: ${userFromDB}`);
            res.redirect('/auth/login');
        })
        .catch(err => console.log(err));
});

//GET /login 
router.get('/login', (req, res) => {
    res.render('auth/login');
});

//POST /login
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    //Checking if both fields contain data
    if (!username || !password){
        res.render('auth/signup', {errorMessage: 'Please input both username and password'});
        return;
    }

    User.findOne({ username })
        .then(user => {
            if (!user) {
                res.render('auth/login', {errorMessage: 'This account does not exist'})
                return;
            }
            else if (bcrypt.compareSync(password, user.password)) {
                req.session.currentUser = user;
                res.redirect('/auth/profile');
            }
            else {
                res.render('auth/login', {errorMessage: 'Incorrect password'})
            }
        })
        .catch(err => console.log(err));
});

//GET /userProfile
router.get('/profile', (req, res) => {
    res.render('auth/userProfile', { userInSession: req.session.currentUser });
});

module.exports = router; 