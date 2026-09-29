const express = require("express");
const axios = require("axios");
const multer = require("multer");
const FormData = require("form-data");
const path = require("path");
require("dotenv").config();

const app = express();
const API_KEY = process.env.VT_API_KEY;
const PORT = Number(process.env.PORT) || 3000;
const VT = "https://www.virustotal.com/api/v3";

if (!API_KEY) {
    console.error("Thiếu VT_API_KEY trong file .env");
    process.exit(1);
}

const WINDOW_MS = 60 * 1000;
const MAX_SCANS = Number(process.env.MAX_SCANS_PER_MINUTE || 5);
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_SIZE_MB || 10) * 1024 * 1024;
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT_SCANS || 5);
const MAX_URL_LENGTH = 2048;
const HTTP_TIMEOUT_MS = 30 * 1000;

// Chỉ tin X-Forwarded-For khi chạy sau proxy (đặt TRUST_PROXY=1). Mặc định không tin để tránh giả mạo IP.
if (process.env.TRUST_PROXY) app.set("trust proxy", Number(process.env.TRUST_PROXY) || 1);
app.disable("x-powered-by");

// ---- Security headers ----
app.use((req, res, next) => {
    res.set({
        "Content-Security-Policy":
            "default-src 'self'; script-src 'self'; " +
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
            "font-src https://fonts.gstatic.com; img-src 'self' data:; " +
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cache-Control": "no-store"
    });
    next();
});

app.use(express.json({ limit: "10kb" }));

// Chỉ phục vụ đúng 2 file giao diện trong public. KHÔNG dùng express.static(__dirname)
// vì sẽ lộ .env và server.js.
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/app.js", (req, res) => res.sendFile(path.join(__dirname, "public", "app.js")));

// ---- Rate limit theo IP + giới hạn số lượt quét đồng thời ----
const history = new Map();
let activeScans = 0;

setInterval(() => {
    const now = Date.now();
    for (const [ip, list] of history) {
        const fresh = list.filter((t) => now - t < WINDOW_MS);
        fresh.length ? history.set(ip, fresh) : history.delete(ip);
    }
}, WINDOW_MS).unref();

function guard(req, res, next) {
    const now = Date.now();
    const ip = req.ip || "unknown";
    const recent = (history.get(ip) || []).filter((t) => now - t < WINDOW_MS);

    if (recent.length >= MAX_SCANS) {
        return res.status(429).json({ error: `Mỗi IP chỉ được quét tối đa ${MAX_SCANS} lần mỗi phút. Vui lòng thử lại sau.` });
    }
    if (activeScans >= MAX_CONCURRENT) {
        return res.status(503).json({ error: "Hệ thống đang bận, vui lòng thử lại sau ít phút." });
    }

    recent.push(now);
    history.set(ip, recent);
    activeScans += 1;
    let released = false;
    const release = () => { if (!released) { released = true; activeScans -= 1; } };
    res.on("finish", release);
    res.on("close", release);
    next();
}

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_FILE_BYTES, files: 1, fields: 0 } });

function handleUpload(req, res, next) {
    upload.single("file")(req, res, (err) => {
        if (!err) return next();
        if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({ error: `File vượt quá giới hạn ${Math.floor(MAX_FILE_BYTES / 1048576)}MB.` });
        }
        return res.status(400).json({ error: "Không thể tải file lên." });
    });
}

// ---- Tiện ích ----
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function validateUrl(input) {
    if (typeof input !== "string") return null;
    const value = input.trim();
    if (!value || value.length > MAX_URL_LENGTH) return null;
    try {
        const u = new URL(value);
        return ["http:", "https:"].includes(u.protocol) ? u.href : null;
    } catch {
        return null;
    }
}

async function waitForAnalysis(id, { maxRetries, delayMs, timeoutMessage }) {
    for (let i = 0; i < maxRetries; i += 1) {
        const r = await axios.get(`${VT}/analyses/${encodeURIComponent(id)}`, {
            headers: { "x-apikey": API_KEY },
            timeout: HTTP_TIMEOUT_MS
        });
        if (r.data?.data?.attributes?.status === "completed") return r.data;
        await sleep(delayMs);
    }
    const e = new Error(timeoutMessage);
    e.code = "ANALYSIS_TIMEOUT";
    e.analysisId = id;
    throw e;
}

// Chỉ trả về những trường giao diện cần, không đẩy nguyên phản hồi của VirusTotal ra ngoài.
function pickResult(data) {
    const a = data?.data?.attributes || {};
    return {
        data: { attributes: { status: a.status, date: a.date, stats: a.stats } },
        meta: { file_info: { sha256: data?.meta?.file_info?.sha256 } }
    };
}

function fail(res, label, error) {
    console.error(`${label}:`, error.response?.status || "", error.code || "", error.message);

    if (error.code === "ANALYSIS_TIMEOUT") {
        return res.status(202).json({ error: error.message, analysisId: error.analysisId, pending: true });
    }
    const status = error.response?.status;
    if (status === 429) return res.status(429).json({ error: "Dịch vụ phân tích đang quá tải, vui lòng thử lại sau." });
    if (status === 400) return res.status(400).json({ error: "Dữ liệu gửi đi không hợp lệ." });
    return res.status(502).json({ error: "Không thể hoàn tất yêu cầu quét. Vui lòng thử lại sau." });
}

// ---- Routes ----
app.post("/scan-url", guard, async (req, res) => {
    try {
        const url = validateUrl(req.body?.url);
        if (!url) return res.status(400).json({ error: "URL không hợp lệ. Chỉ chấp nhận http:// hoặc https://" });

        const r = await axios.post(`${VT}/urls`, new URLSearchParams({ url }), {
            headers: { "x-apikey": API_KEY, "Content-Type": "application/x-www-form-urlencoded" },
            timeout: HTTP_TIMEOUT_MS
        });

        const result = await waitForAnalysis(r.data.data.id, {
            maxRetries: 20,
            delayMs: 2500,
            timeoutMessage: "URL đang được phân tích lâu hơn dự kiến. Vui lòng thử lại sau."
        });
        return res.json(pickResult(result));
    } catch (error) {
        return fail(res, "URL ERROR", error);
    }
});

app.post("/scan-file", guard, handleUpload, async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "Chưa chọn file" });

        const form = new FormData();
        // Không dùng tên file gốc từ người dùng khi gửi đi
        form.append("file", req.file.buffer, { filename: "upload.bin" });

        const r = await axios.post(`${VT}/files`, form, {
            headers: { ...form.getHeaders(), "x-apikey": API_KEY },
            maxBodyLength: MAX_FILE_BYTES + 1024 * 1024,
            timeout: 60 * 1000
        });

        const result = await waitForAnalysis(r.data.data.id, {
            maxRetries: 40,
            delayMs: 3000,
            timeoutMessage: "File đang được phân tích, cần thêm thời gian. Vui lòng đợi rồi thử lại."
        });
        return res.json(pickResult(result));
    } catch (error) {
        return fail(res, "FILE ERROR", error);
    }
});

// 404 và lỗi chung: không lộ stack trace
app.use((req, res) => res.status(404).json({ error: "Không tìm thấy." }));
app.use((err, req, res, next) => {
    console.error("UNHANDLED:", err.message);
    res.status(err.status === 400 ? 400 : 500).json({ error: "Yêu cầu không hợp lệ hoặc lỗi hệ thống." });
});

app.listen(PORT, () => console.log(`Server chạy tại http://localhost:${PORT}`));
