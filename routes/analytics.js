const express = require('express')
const controller = require('../controllers/analytics')
const router = express.Router()

//localhost:5000/api/analytics/analytics
router.get('/analytics', controller.analytics)
//localhost:5000/api/analytics/overview
router.get('/overview', controller.overview)

module.exports = router