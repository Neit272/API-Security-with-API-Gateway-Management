import express from 'express';
import helmet from 'helmet';
import dotenv from 'dotenv';
import apiRoutes from './routes/index.js';
import { saveLog } from './SQLite3/logger.js';
import fs from 'fs'; // Để ghi log vào file nếu cần

dotenv.config(); // Configure dotenv to load .env variables

const PORT = process.env.server_local_port;

const app = express();
app.disable('x-powered-by');

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// API chính
app.use('/api', apiRoutes);

// Route nhận log từ Kong
app.post('/logs', (req, res) => {
  const log = req.body;  // <-- Đây là dòng bạn thiếu
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

// Default route
app.get('/', (req, res) => {
  res.send('API Server is running!');
});

// Dashboard tĩnh (nếu có)
app.use('/dashboard', express.static('dashboard'));

// Khởi chạy server
app.listen(PORT, '127.0.0.1', () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
