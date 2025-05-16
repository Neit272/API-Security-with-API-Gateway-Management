import express from 'express';
const router = express.Router();

// Public API
router.get('/public', (_, res) => {
  res.json({ message: 'This is a public API response.' });
});

// API with Basic Authentication
router.get('/secure', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey === '123456') {
    res.json({ message: 'Secure data access granted.' });
  } else {
    res.status(401).json({ error: 'Unauthorized – Invalid API Key' });
  }
});

export default router;
