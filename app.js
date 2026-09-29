const $ = (id) => document.getElementById(id);
const tabs = document.querySelectorAll(".tab");
const tabButtons = document.querySelectorAll("[data-tab-btn]");
const statusEl = $("status");
const statusNoteEl = $("statusNote");
const statsEl = $("stats");
const metaEl = $("meta");
const loadingWrapEl = $("loadingWrap");
const urlInput = $("urlInput");
const fileInput = $("fileInput");
const urlScanBtn = $("urlScanBtn");
const fileScanBtn = $("fileScanBtn");

const MAX_FILE_MB = 10; // khớp với MAX_FILE_SIZE_MB ở server

tabButtons.forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tabBtn)));
urlScanBtn.addEventListener("click", scanURL);
fileScanBtn.addEventListener("click", scanFile);
urlInput.addEventListener("keydown", (e) => { if (e.key === "Enter") scanURL(); });

function switchTab(name) {
    tabs.forEach((t) => t.classList.remove("active"));
    tabButtons.forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
    });
    $(name).classList.add("active");
    const btn = document.querySelector(`[data-tab-btn="${name}"]`);
    btn.classList.add("active");
    btn.setAttribute("aria-selected", "true");
    resetResult();
}

function setBanner(text, cls, note) {
    statusEl.textContent = text;
    statusEl.className = `status-banner ${cls}`;
    statusNoteEl.textContent = note;
}

function clearDetails() {
    statsEl.replaceChildren();
    statsEl.classList.add("hidden");
    metaEl.replaceChildren();
}

const showLoadingBar = () => loadingWrapEl.classList.remove("hidden");
const hideLoadingBar = () => loadingWrapEl.classList.add("hidden");

function resetResult() {
    setBanner("Sẵn sàng quét.", "status-neutral", "Nhập URL hoặc chọn file để bắt đầu.");
    clearDetails();
    hideLoadingBar();
}

function setLoading(message) {
    setBanner(message, "status-neutral", "Hệ thống đang chờ kết quả phân tích.");
    clearDetails();
    showLoadingBar();
}

function getErrorMessage(data, fallback) {
    const e = data?.error;
    if (typeof e === "string" && e.trim()) return e;
    if (e && typeof e === "object" && typeof e.message === "string" && e.message.trim()) return e.message;
    return fallback;
}

function makeEl(tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    el.textContent = text; // textContent: chống XSS
    return el;
}

function renderStats(stats) {
    const cards = [
        ["Độc hại", stats.malicious],
        ["Đáng ngờ", stats.suspicious],
        ["Không phát hiện", stats.undetected],
        ["Vô hại", stats.harmless]
    ];
    statsEl.replaceChildren(...cards.map(([label, value]) => {
        const card = makeEl("div", "stat-card");
        card.append(makeEl("span", "stat-label", label), makeEl("span", "stat-value", String(Number(value) || 0)));
        return card;
    }));
    statsEl.classList.remove("hidden");
}

function renderMeta(data) {
    const lines = [];
    const a = data?.data?.attributes || {};
    if (a.date) lines.push(`Thời gian quét: ${new Date(a.date * 1000).toLocaleString("vi-VN")}`);
    if (a.status) lines.push(`Trạng thái phân tích: ${a.status === "completed" ? "hoàn tất" : a.status}`);
    if (data?.meta?.file_info?.sha256) lines.push(`SHA256: ${data.meta.file_info.sha256}`);
    if (data?.analysisId) lines.push(`Mã phân tích: ${data.analysisId}`);
    if (data?.pending) lines.push("Trạng thái: đang chờ");
    metaEl.replaceChildren(...lines.map((l) => makeEl("div", "meta-item", l)));
}

function showError(data, title) {
    hideLoadingBar();
    setBanner(title, "status-danger", getErrorMessage(data, "Hệ thống không thể hoàn tất yêu cầu này."));
    clearDetails();
}

function showPending(data) {
    showLoadingBar();
    setBanner("Đang phân tích thêm.", "status-warning", getErrorMessage(data, "Cần thêm thời gian để hoàn tất quét."));
    statsEl.replaceChildren();
    statsEl.classList.add("hidden");
    renderMeta(data);
}

function showResult(data) {
    hideLoadingBar();
    const stats = data?.data?.attributes?.stats;
    if (!stats) return showError(data, "Không lấy được kết quả quét.");

    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;

    if (malicious > 0) {
        setBanner("Phát hiện nguy cơ.", "status-danger", `Có ${malicious} engine đánh dấu file hoặc URL này là nguy hiểm.`);
    } else if (suspicious > 0) {
        setBanner("Cần kiểm tra thêm.", "status-warning", `Có ${suspicious} engine đánh dấu đáng ngờ. Nên kiểm tra kỹ hơn trước khi mở hoặc tải xuống.`);
    } else {
        setBanner("Tạm thời an toàn.", "status-safe", "Không có engine nào đánh dấu mã độc trong lần quét này. Kết quả này không đảm bảo an toàn tuyệt đối.");
    }
    renderStats(stats);
    renderMeta(data);
}

function validateUrlClient(value) {
    try {
        return ["http:", "https:"].includes(new URL(value).protocol);
    } catch {
        return false;
    }
}

async function runScan(endpoint, options, loadingText, failText) {
    try {
        urlScanBtn.disabled = fileScanBtn.disabled = true;
        setLoading(loadingText);

        const response = await fetch(endpoint, options);
        let data = {};
        try { data = await response.json(); } catch { /* phản hồi không phải JSON */ }

        if (response.status === 202) return showPending(data);
        if (!response.ok) return showError(data, failText);
        showResult(data);
    } catch {
        showError({ error: "Không kết nối được tới server. Vui lòng kiểm tra mạng và thử lại." }, "Lỗi kết nối.");
    } finally {
        urlScanBtn.disabled = fileScanBtn.disabled = false;
    }
}

function scanURL() {
    const url = urlInput.value.trim();
    if (!url) return showError({ error: "Vui lòng nhập một URL để quét." }, "Bạn chưa nhập URL.");
    if (!validateUrlClient(url)) return showError({ error: "URL phải bắt đầu bằng http:// hoặc https://" }, "URL không hợp lệ.");

    runScan("/scan-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
    }, "Đang quét URL...", "Quét URL thất bại.");
}

function scanFile() {
    const file = fileInput.files[0];
    if (!file) return showError({ error: "Vui lòng chọn một file để quét." }, "Bạn chưa chọn file.");
    if (file.size > MAX_FILE_MB * 1024 * 1024) {
        return showError({ error: `File vượt quá giới hạn ${MAX_FILE_MB}MB.` }, "File quá lớn.");
    }

    const formData = new FormData();
    formData.append("file", file);
    runScan("/scan-file", { method: "POST", body: formData }, "Đang quét file...", "Quét file thất bại.");
}
