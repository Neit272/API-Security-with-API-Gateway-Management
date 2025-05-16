import express from 'express';
const router = express.Router();

// Public API
router.get('/public', (_, res) => {
  res.json({ message: 'This is a public API response.' });
});

// API endpoint now secured by Kong (API Key)
router.get('/secure', (req, res) => {
  // If the request reaches here, Kong has successfully authenticated it.
  // Kong forwards information about the authenticated consumer in headers.
  const consumerUsername = req.headers['x-consumer-username']; // Kong adds this    
  const consumerId = req.headers['x-consumer-id']; // Kong adds this

  res.json({
    message: 'Secure data access granted via Kong.',
    consumerUsername: consumerUsername || 'N/A',
    consumerId: consumerId || 'N/A'
  });
});

export default router;