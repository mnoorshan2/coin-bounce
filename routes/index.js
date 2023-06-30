const express = require('express');
const router = express.Router();
const AuthController = require('../controller/authController');
const auth = require('../middleware/auth');
const authController = require('../controller/authController');
const blogController = require('../controller/blogController');
const comment = require('../models/comment');
const commentController = require('../controller/commentController');

// testing
// user
// register
router.post('/register', AuthController.register);
// login
router.post('/login', AuthController.login);
// logout
router.post('/logout', auth, AuthController.logout)
// refresh
router.get('/refresh', authController.refresh);

// blog
router.post('/blog', auth, blogController.create);

// get all
router.get('/blog/all', auth, blogController.getAll);

// get blog by id
router.get('/blog/:id', auth, blogController.getById);

// update blog
router.put('/blog', auth, blogController.update);

// delete
router.delete('/blog/:id', auth, blogController.delete);
// crud
// create
// read all blogs
// read blog by id
// update
// delete

// comment
router.post('/comment', auth, commentController.create);
// create comment
// read comment by by blog id
router.get('/comment/:id', auth, commentController.getById);

module.exports = router;