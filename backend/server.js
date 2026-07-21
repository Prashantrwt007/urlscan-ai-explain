// backend/server.js
// Express API gateway. Receives a URL from the frontend, spawns the
// Python inference script (model.py), and returns the classification.

const express = require('express');
const cors = require('cors');
const { spawn } = require('child_process');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const PYTHON_BIN = process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');

app.use(cors());
app.use(express.json());

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok' });
});

app.post('/api/analyze', (req, res) => {
    const { url } = req.body;

    if (!url || typeof url !== 'string' || !url.trim()) {
        return res.status(400).json({ error: 'A valid URL string is required.' });
    }

    const scriptPath = path.join(__dirname, 'model.py');
    const pythonProcess = spawn(PYTHON_BIN, [scriptPath, url.trim()]);

    let stdout = '';
    let stderr = '';

    pythonProcess.stdout.on('data', (data) => {
        stdout += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
        stderr += data.toString();
    });

    pythonProcess.on('close', (code) => {
        if (code !== 0) {
            console.error('Python process exited with code', code, stderr);
            return res.status(500).json({ error: 'Model inference failed.', details: stderr });
        }
        try {
            const result = JSON.parse(stdout);
            res.json(result);
        } catch (err) {
            res.status(500).json({
                error: 'Failed to parse model output.',
                details: stdout,
            });
        }
    });

    pythonProcess.on('error', (err) => {
        res.status(500).json({ error: 'Could not start Python process.', details: err.message });
    });
});

app.listen(PORT, '127.0.0.1', () => {
    console.log(`URL Phishing Detector API running on http://127.0.0.1:${PORT}`);
});
