import express from 'express';
import helmet from 'helmet';
import dotenv from 'dotenv';
import apiRoutes from './routes/index.js';
import { saveLog } from './SQLite3/db.js';

dotenv.config();

const PORT = process.env.server_local_port;

const app = express();
app.disable('x-powered-by');

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api', apiRoutes);

app.post('/logs', (req, res) => {
  const log = req.body;
  console.log('Received log:', req.body);
  const data = {
    client_ip: log.client_ip,
    request_uri: log.request?.uri,
    status: log.response?.status,
    response_time: log.latencies?.proxy,
    service: log.service?.name || 'unknown',
  };

  saveLog(data);
  res.status(200).send('Log received');
});

app.get('/', (req, res) => {
  res.send('API Server is running!');
});

app.use('/dashboard', express.static('dashboard'));

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
