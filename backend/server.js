// backend/server.js
// Express API gateway. Receives a URL from the frontend, spawns the
// Python inference script (model.py), and returns the classification.
// Also proxies the classification result to Gemini for a plain-language
// explanation (see /api/explain).

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { spawn } = require('child_process');
const path = require('path');
const { GoogleGenAI } = require('@google/genai');

const app = express();
const PORT = process.env.PORT || 5000;
const PYTHON_BIN = process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');

const genAI = process.env.GEMINI_API_KEY
    ? new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY })
    : null;

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

app.post('/api/explain', async (req, res) => {
    const { url, risk_score, status, indicators } = req.body;

    if (!url || risk_score === undefined || !status || !indicators) {
        return res.status(400).json({ error: 'Missing analyze result fields (url, risk_score, status, indicators).' });
    }

    if (!genAI) {
        return res.status(500).json({ error: 'GEMINI_API_KEY is not set on the server.' });
    }

    const prompt = `You are a security analyst explaining a phishing-detection result to a non-technical user.

URL: ${url}
Risk score: ${risk_score}/100
Classification: ${status}
Structural indicators detected: ${indicators.join(', ')}

Write a short, plain-language explanation (3-5 sentences) of why this URL received this score. Reference the specific indicators. Do not repeat the raw numbers back verbatim -- explain what they mean in practice. If the URL looks safe, say so plainly and briefly explain what made it look clean.`;

    async function callGemini(model) {
        return genAI.models.generateContent({ model, contents: prompt });
    }

    const attempts = [
        { model: 'gemini-2.5-flash-lite', wait: 0 },
        { model: 'gemini-flash-latest', wait: 1500 },
        { model: 'gemini-2.5-flash-lite', wait: 3000 },
        { model: 'gemini-flash-latest', wait: 5000 },
    ];

    let response;
    let lastErr;
    for (const attempt of attempts) {
        if (attempt.wait) await new Promise((r) => setTimeout(r, attempt.wait));
        try {
            response = await callGemini(attempt.model);
            lastErr = null;
            break;
        } catch (err) {
            lastErr = err;
            const permanent = err.message && (err.message.includes('NOT_FOUND') || err.message.includes('400') || err.message.includes('API_KEY_INVALID'));
            if (permanent) break;
        }
    }

    if (lastErr) {
        console.error('Gemini error:', lastErr.message);
        return res.status(500).json({ error: 'Failed to generate explanation.', details: lastErr.message });
    }

    try {
        res.json({ explanation: response.text });
    } catch (err) {
        console.error('Gemini error:', err.message);
        res.status(500).json({ error: 'Failed to generate explanation.', details: err.message });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`URL Phishing Detector API running on port ${PORT}`);
});
