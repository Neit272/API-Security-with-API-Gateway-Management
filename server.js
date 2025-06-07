import express from "express";
import helmet from "helmet";
import dotenv from "dotenv";
import axios from "axios";
import apiRoutes from "./routes/index.js";
import { saveLog } from "./SQLite3/db.js";

dotenv.config();

const PORT = process.env.server_local_port;

const app = express();
app.disable("x-powered-by");

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/api", apiRoutes);

app.post("/logs", async (req, res) => {
  const log = req.body;
  console.log("Received log:", req.body);

  const splunkHecUrl = process.env.SPLUNK_HEC_URL;
  const splunkHecToken = process.env.SPLUNK_HEC_TOKEN;

  let splunkForwarded = false;
  let splunkConfigMissing = false;

  if (!splunkHecUrl || !splunkHecToken) {
    console.error(
      "Splunk HEC URL or Token is not configured in environment variables."
    );
    splunkConfigMissing = true;
  } else {
    const splunkPayload = {
      event: log,
      sourcetype: "_json",
    };

    try {
      await axios.post(splunkHecUrl, splunkPayload, {
        headers: {
          Authorization: `Splunk ${splunkHecToken}`,
          "Content-Type": "application/json",
        },
        timeout: 5000,
      });
      console.log("Log successfully sent to Splunk HEC.");
      splunkForwarded = true;
    } catch (error) {
      console.error(
        "Error sending log to Splunk HEC:",
        error.code === "ECONNRESET"
          ? "Connection was reset by Splunk (ECONNRESET)"
          : error.response
          ? error.response.data
          : error.message
      );
      if (error.response && error.response.data) {
        console.error("Splunk HEC Response:", error.response.data);
      }
    }
  }
  try {
    const dataToSave = {
      client_ip: log.client_ip,
      request_uri: log.request?.uri,
      status: log.response?.status,
      response_time: log.latencies?.proxy,
      service: log.service?.name || "unknown",
    };
    saveLog(dataToSave);
    console.log("Log saved locally.");
  } catch (dbError) {
    console.error("Error saving log locally:", dbError);
  }

  if (splunkConfigMissing) {
    res
      .status(200)
      .send("Log received. Splunk HEC not configured; log saved locally.");
  } else if (splunkForwarded) {
    res.status(200).send("Log received and forwarded to Splunk.");
  } else {
    res
      .status(200)
      .send("Log received. Error forwarding to Splunk; log saved locally.");
  }
});

app.get("/", (req, res) => {
  res.send("API Server is running!");
});

app.use("/dashboard", express.static("dashboard"));

app.listen(PORT, "127.0.0.1", () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
