import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import apiRoutes from './routes/api.js';

dotenv.config(); // Configure dotenv to load .env variables

const PORT = process.env.server_local_port;

const app = express();
app.disable('x-powered-by'); // Disable 'X-Powered-By' header for security reasons

// Use Helmet to help secure Express apps by setting various HTTP headers
app.use(helmet());

// Enable CORS for all routes
app.use(cors());
app.use(express.json());
app.use(express.json());

// Use API routes
app.use('/api', apiRoutes);

// Default route
app.get('/', (req, res) => {
  res.send('API Server is running!');
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});