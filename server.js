import express from 'express';
import helmet from 'helmet';
import dotenv from 'dotenv';
import apiRoutes from './routes/index.js';

dotenv.config(); // Configure dotenv to load .env variables

const PORT = process.env.server_local_port;

const app = express();
app.disable('x-powered-by');

app.use(helmet());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api', apiRoutes);

// Default route
app.get('/', (req, res) => {
  res.send('API Server is running!');
});

app.use('/dashboard', express.static('dashboard'));

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Server running at http://localhost:${PORT}`);
});