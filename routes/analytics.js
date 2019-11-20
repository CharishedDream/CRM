const express = require('express')
const passport = require('passport')
const controller = require('../controllers/analytics')
const router = express.Router()

//localhost:5000/api/analytics/analytics
router.get('/analytics', passport.authenticate('jwt', {session: false}), controller.analytics)
//localhost:5000/api/analytics/overview
router.get('/overview', passport.authenticate('jwt', {session: false}), controller.overview)

module.exports = router