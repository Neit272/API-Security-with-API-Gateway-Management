import express from 'express';

const router = express.Router();

router.get('/info', (req, res) => {
    res.json({
        message: 'This is a secure endpoint, accessible only with a valid JWT token.',
        user: req.user || null,
    });
})

export default router;